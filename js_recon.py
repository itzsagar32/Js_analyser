

import os
import re
import math
import json
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import jsbeautifier
from flask import Flask, request, jsonify, render_template_string

# Disable SSL warnings for targets with self-signed certificates
requests.packages.urllib3.disable_warnings()

# --- CONFIGURATION & PATTERNS ---

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

PATTERNS = {
    "High-Confidence Secrets": [
        r'AKIA[0-9A-Z]{16}',
        r'AIza[0-9A-Za-z\-_]{35}',
        r'sk_live_[0-9a-zA-Z]{24}',
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'
    ],
    "Generic Keys & Crypto": [
        r'(?i)(?:api_key|apikey|secret|token|password|passwd|auth|aes_key|iv|salt|encryption_key)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-\.\=\+\/]{8,})["\']',
        r'(?i)CryptoJS\.AES\.(?:encrypt|decrypt)\([^)]+\)',
    ],
    "Endpoints & Paths": [
        r'["\'](\/(?:api|v1|v2|v3|admin|auth|user|users|graphql|internal|debug)[a-zA-Z0-9_\-\/\.\?\=\&]*)["\']',
        r'["\'](\/[a-zA-Z0-9_\-\/]+\.(?:json|xml|yaml|yml|config|env|bak))["\']'
    ],
    "External URLs & Storage": [
        r'https?:\/\/[a-zA-Z0-9\-\.]+\.s3\.amazonaws\.com[^\s"\']*',
        r'https?:\/\/[a-zA-Z0-9\-\.]+\.firebaseio\.com[^\s"\']*',
        r'https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[a-zA-Z0-9_\-\/\.\?\=\&]*)?'
    ],
    "API Calls & Sinks": [
        r'fetch\(\s*["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
        r'\.open\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
    ]
}

# --- HELPER FUNCTIONS ---

def calculate_entropy(data):
    """Calculates Shannon entropy to distinguish random secrets from plain text."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def sanitize_filename(name):
    """Converts unsafe domain/path characters into secure filenames/folders."""
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)

def analyze_code(code):
    """Scans code against regex rules and filters low-entropy matches."""
    findings = {category: set() for category in PATTERNS}
    
    for category, regex_list in PATTERNS.items():
        for pattern in regex_list:
            matches = re.findall(pattern, code)
            for match in matches:
                val = match[0] if isinstance(match, tuple) else match
                val = val.strip()
                
                if len(val) < 4 or val.startswith('//'):
                    continue
                    
                if category == "Generic Keys & Crypto" and "CryptoJS" not in val:
                    if calculate_entropy(val) < 3.2:
                        continue
                        
                findings[category].add(val)
                
    return {k: sorted(list(v)) for k, v in findings.items() if v}

def process_subdomain(target, output_dir, session):
    """Harvests, downloads, beautifies, and analyzes JS assets for a subdomain."""
    if not target.startswith(('http://', 'https://')):
        target_url = f"https://{target}"
    else:
        target_url = target

    sub_folder = os.path.join(output_dir, sanitize_filename(target))
    os.makedirs(sub_folder, exist_ok=True)
    sub_results = {}
    
    try:
        resp = session.get(target_url, headers=HEADERS, timeout=8, verify=False)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        js_sources = {}
        
        # 1. Harvest Inline Scripts
        inline_scripts = [s.string for s in soup.find_all('script', src=False) if s.string]
        if inline_scripts:
            js_sources["inline_scripts.js"] = "\n// --- INLINE SCRIPT ---\n".join(inline_scripts)

        # 2. Harvest External Scripts & Check Source Maps
        external_urls = set()
        for script in soup.find_all('script', src=True):
            external_urls.add(urljoin(target_url, script['src']))
            
        for js_url in external_urls:
            try:
                js_resp = session.get(js_url, headers=HEADERS, timeout=6, verify=False)
                if js_resp.status_code == 200:
                    parsed = urlparse(js_url)
                    fname = os.path.basename(parsed.path) or "index.js"
                    if not fname.endswith('.js'):
                        fname += ".js"
                    unique_fname = f"{abs(hash(js_url)) % 10000}_{sanitize_filename(fname)}"
                    js_sources[unique_fname] = js_resp.text
                    
                    # Optional: Source map lookup
                    map_resp = session.get(js_url + ".map", headers=HEADERS, timeout=4, verify=False)
                    if map_resp.status_code == 200:
                        js_sources[unique_fname + ".map.json"] = map_resp.text
            except requests.RequestException:
                continue

        # 3. Beautify & Analyze Each Source
        for filename, raw_code in js_sources.items():
            if filename.endswith('.json'):
                beautified = raw_code
            else:
                beautified = jsbeautifier.beautify(raw_code)
                
            filepath = os.path.join(sub_folder, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(beautified)
                
            analysis = analyze_code(beautified)
            if analysis:
                sub_results[filename] = analysis

    except requests.RequestException as e:
        sub_results["error"] = f"Connection failed: {str(e)}"
        
    return target, sub_results

def generate_markdown_report(report_data, output_dir):
    """Exports structured results into a readable Markdown report."""
    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# JS Recon & Static Analysis Report\n\n")
        for sub, files in report_data.items():
            f.write(f"## Target: `{sub}`\n")
            if not files:
                f.write("_No interesting artifacts found._\n\n")
                continue
            if "error" in files:
                f.write(f"> **Error:** {files['error']}\n\n")
                continue
            for filename, categories in files.items():
                f.write(f"### File: `{filename}`\n")
                for category, items in categories.items():
                    f.write(f"**{category}** ({len(items)})\n")
                    for item in items:
                        f.write(f"- `{item}`\n")
                    f.write("\n")
            f.write("---\n\n")
    return md_path

def run_scanner(subdomains, output_dir="recon_output", threads=10):
    """Manages multi-threaded execution across multiple target subdomains."""
    os.makedirs(output_dir, exist_ok=True)
    full_report = {}
    session = requests.Session()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_sub = {
            executor.submit(process_subdomain, sub, output_dir, session): sub 
            for sub in subdomains
        }
        for future in as_completed(future_to_sub):
            sub, results = future.result()
            full_report[sub] = results

    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=4)
        
    generate_markdown_report(full_report, output_dir)
    return full_report

# --- WEB UI & DASHBOARD TEMPLATE ---

SCAN_STATE = {"status": "idle", "progress": 0, "completed": 0, "total": 0, "results": {}}

UI_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JS Recon & Static Analyzer</title>
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-surface: #111827;
            --border-color: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #0ea5e9;
            --accent-hover: #0284c7;
            --code-bg: #030712;
            --code-text: #34d399;
            --error-color: #f87171;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.5;
        }

        header {
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            font-size: 20px;
            font-weight: 600;
            color: #f9fafb;
            margin: 0;
        }

        .subtitle {
            font-size: 13px;
            color: var(--text-muted);
        }

        .card {
            background-color: var(--bg-surface);
            border: 1px solid var(--border-color);
            padding: 24px;
            border-radius: 8px;
            margin-bottom: 24px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
        }

        textarea {
            width: 100%;
            height: 140px;
            background-color: var(--bg-base);
            color: var(--text-main);
            border: 1px solid #374151;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            box-sizing: border-box;
            resize: vertical;
        }

        textarea:focus {
            outline: none;
            border-color: var(--accent);
        }

        button {
            background-color: var(--accent);
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 500;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s ease;
        }

        button:hover {
            background-color: var(--accent-hover);
        }

        button:disabled {
            background-color: #374151;
            cursor: not-allowed;
        }

        #status {
            font-size: 14px;
            font-weight: 500;
            color: var(--accent);
            display: none;
        }

        .badge {
            background-color: var(--border-color);
            color: var(--accent);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
        }

        pre {
            background-color: var(--code-bg);
            color: var(--code-text);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            border: 1px solid var(--border-color);
            margin-top: 6px;
        }

        .error-text {
            color: var(--error-color);
        }

        .actions-row {
            margin-top: 15px;
            display: flex;
            align-items: center;
            gap: 16px;
        }
    </style>
</head>
<body>

    <header>
        <h1>JS Recon Dashboard</h1>
        <span class="subtitle">Security Research Companion</span>
    </header>

    <div class="card">
        <form id="reconForm">
            <label for="subdomains">Target Subdomains (one per line):</label>
            <textarea id="subdomains" placeholder="example.com
api.example.com"></textarea>
            
            <div class="actions-row">
                <button type="submit" id="submitBtn">Start Recon Scan</button>
                <div id="status">Initializing background scan...</div>
            </div>
        </form>
    </div>

    <div id="resultsContainer"></div>

    <script>
        document.getElementById('reconForm').onsubmit = async (e) => {
            e.preventDefault();
            const text = document.getElementById('subdomains').value.trim();
            if (!text) return;

            const btn = document.getElementById('submitBtn');
            const status = document.getElementById('status');
            
            btn.disabled = true;
            status.style.display = 'inline-block';
            status.innerText = "Triggering scan job...";

            await fetch('/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({subdomains: text})
            });

            const pollInterval = setInterval(async () => {
                const res = await fetch('/status');
                const data = await res.json();

                if (data.status === 'completed') {
                    clearInterval(pollInterval);
                    status.innerText = "Scan completed successfully!";
                    btn.disabled = false;
                    renderResults(data.results);
                } else {
                    status.innerText = `Scanning... (${data.completed} / ${data.total} targets processed)`;
                }
            }, 1500);
        };

        function renderResults(results) {
            const container = document.getElementById('resultsContainer');
            container.innerHTML = '<h2 style="font-size: 18px; margin-bottom: 16px;">Scan Results</h2>';
            
            for (const [sub, files] of Object.entries(results)) {
                let cardHTML = `<div class="card"><h3 style="margin-top:0; color: #f9fafb;">Target: ${sub}</h3>`;
                
                if (!files || Object.keys(files).length === 0) {
                    cardHTML += `<p style="color: var(--text-muted); margin: 0;">No interesting artifacts found or target unreachable.</p>`;
                } else if (files.error) {
                    cardHTML += `<p class="error-text">${files.error}</p>`;
                } else {
                    for (const [fname, categories] of Object.entries(files)) {
                        cardHTML += `<h4 style="margin: 16px 0 8px 0;">File: <span class="badge">${fname}</span></h4>`;
                        for (const [category, items] of Object.entries(categories)) {
                            cardHTML += `<div style="font-size: 13px; margin-top: 8px;"><strong>${category}</strong></div>`;
                            cardHTML += `<pre>${items.join('\\n')}</pre>`;
                        }
                    }
                }
                cardHTML += `</div>`;
                container.innerHTML += cardHTML;
            }
        }
    </script>
</body>
</html>
"""

def background_scanner(subdomains):
    """Executes the scan in a background thread to prevent web UI request timeouts."""
    SCAN_STATE["status"] = "running"
    SCAN_STATE["total"] = len(subdomains)
    SCAN_STATE["completed"] = 0
    SCAN_STATE["results"] = {}
    
    output_dir = "recon_output"
    os.makedirs(output_dir, exist_ok=True)
    full_report = {}
    session = requests.Session()
    
    for sub in subdomains:
        sub, results = process_subdomain(sub, output_dir, session)
        full_report[sub] = results
        SCAN_STATE["completed"] += 1
        SCAN_STATE["results"] = full_report

    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=4)
        
    generate_markdown_report(full_report, output_dir)
    SCAN_STATE["status"] = "completed"

def start_web_ui():
    """Initializes and runs the local Flask web server."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(UI_TEMPLATE)

    @app.route("/start", methods=["POST"])
    def start_scan():
        data = request.json
        raw = data.get("subdomains", "")
        subdomains = [line.strip() for line in raw.splitlines() if line.strip()]
        if subdomains and SCAN_STATE["status"] != "running":
            threading.Thread(target=background_scanner, args=(subdomains,)).start()
        return jsonify({"success": True})

    @app.route("/status")
    def get_status():
        return jsonify({
            "status": SCAN_STATE["status"],
            "total": SCAN_STATE.get("total", 0),
            "completed": SCAN_STATE.get("completed", 0),
            "results": SCAN_STATE.get("results", {})
        })

    print("[*] Minimalist Web UI active at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)

# --- CLI ENTRY POINT ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated JS Recon & Static Analysis Tool")
    parser.add_argument("-f", "--file", default="subdomains.txt", help="Path to subdomains file (CLI mode)")
    parser.add_argument("-o", "--output", default="recon_output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--ui", action="store_true", help="Launch the local Web UI dashboard")
    
    args = parser.parse_args()

    if args.ui:
        start_web_ui()
    else:
        if not os.path.exists(args.file):
            print(f"[!] Error: '{args.file}' not found. Create it or launch with --ui.")
        else:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"[*] Scanning {len(targets)} targets via CLI...")
            run_scanner(targets, output_dir=args.output, threads=args.threads)
            print("[✓] Scan complete! Check 'recon_output/' for results.")