import os
import re
import math
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import jsbeautifier
from flask import Flask, request, render_template_string

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings()

# --- CONFIGURATION & PATTERNS ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

PATTERNS = {
    "High-Confidence Secrets": [
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key
        r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
        r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Live Key
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # JWT Token
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
        r'(?:innerHTML|outerHTML|document\.write|eval\()'  # Potential DOM XSS sinks
    ]
}

# --- HELPER FUNCTIONS ---

def calculate_entropy(data):
    """Calculates Shannon entropy to check if a string looks like a random secret."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def sanitize_filename(name):
    """Replaces unsafe characters with underscores for folder/file names."""
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)

def analyze_code(code):
    """Scans JavaScript code using regex and filters weak secrets via entropy."""
    findings = {category: set() for category in PATTERNS}
    
    for category, regex_list in PATTERNS.items():
        for pattern in regex_list:
            matches = re.findall(pattern, code)
            for match in matches:
                # If regex has capture groups, re.findall returns a tuple; grab the string
                val = match[0] if isinstance(match, tuple) else match
                val = val.strip()
                
                if len(val) < 4 or val.startswith('//'):
                    continue
                
                # Filter out low-entropy placeholders in generic keys (e.g., "password123")
                if category == "Generic Keys & Crypto" and "CryptoJS" not in val:
                    if calculate_entropy(val) < 3.2:
                        continue
                        
                findings[category].add(val)
                
    return {k: sorted(list(v)) for k, v in findings.items() if v}

def process_subdomain(target, output_dir):
    """Fetches a subdomain, extracts inline & external JS, beautifies, and analyzes."""
    if not target.startswith(('http://', 'https://')):
        target_url = f"https://{target}"
    else:
        target_url = target

    sub_folder = os.path.join(output_dir, sanitize_filename(target))
    os.makedirs(sub_folder, exist_ok=True)
    
    sub_results = {}
    
    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=10, verify=False)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        js_sources = {}  # Maps source name -> raw JS content
        
        # 1. Extract Inline Scripts
        inline_scripts = [s.string for s in soup.find_all('script', src=False) if s.string]
        if inline_scripts:
            combined_inline = "\n// --- NEXT INLINE SCRIPT ---\n".join(inline_scripts)
            js_sources["inline_scripts.js"] = combined_inline

        # 2. Gather External Script URLs
        external_urls = set()
        for script in soup.find_all('script', src=True):
            external_urls.add(urljoin(target_url, script['src']))
            
        for js_url in external_urls:
            try:
                js_resp = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
                if js_resp.status_code == 200:
                    parsed = urlparse(js_url)
                    fname = os.path.basename(parsed.path) or "index.js"
                    if not fname.endswith('.js'):
                        fname += ".js"
                    # Prefix with hash of URL to avoid overwriting files with same name
                    unique_fname = f"{abs(hash(js_url)) % 10000}_{sanitize_filename(fname)}"
                    js_sources[unique_fname] = js_resp.text
            except requests.RequestException:
                continue

        # 3. Beautify, Save, and Analyze each JS source
        for filename, raw_code in js_sources.items():
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
    """Converts the JSON dictionary into a readable Markdown report."""
    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# JavaScript Security Recon Report\n\n")
        
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

def run_scanner(subdomains, output_dir="recon_output", threads=5):
    """Orchestrates multi-threaded scanning across all subdomains."""
    os.makedirs(output_dir, exist_ok=True)
    full_report = {}
    
    print(f"[*] Starting scan on {len(subdomains)} targets using {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all tasks to the thread pool
        future_to_sub = {
            executor.submit(process_subdomain, sub, output_dir): sub 
            for sub in subdomains
        }
        
        for future in as_completed(future_to_sub):
            sub, results = future.result()
            full_report[sub] = results
            print(f"[+] Finished: {sub} (Files with findings: {len(results)})")

    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(full_report, f, indent=4)
        
    md_path = generate_markdown_report(full_report, output_dir)
    print(f"\n[✓] Done! Reports saved to:\n  - {json_path}\n  - {md_path}")
    return full_report

# --- OPTIONAL WEB UI (FLASK) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>JS Recon Helper</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #38bdf8; }
        textarea { width: 100%; height: 120px; background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 10px; border-radius: 6px; font-family: monospace; }
        button { background: #0284c7; color: white; border: none; padding: 10px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #0369a1; }
        .card { background: #1e293b; border: 1px solid #334155; padding: 15px; border-radius: 8px; margin-top: 20px; }
        .badge { background: #334155; color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        pre { background: #0f172a; padding: 10px; border-radius: 4px; overflow-x: auto; color: #a7f3d0; }
    </style>
</head>
<body>
    <h1>JS Static Analyzer & Recon Helper</h1>
    <form method="POST">
        <label>Enter subdomains (one per line):</label><br><br>
        <textarea name="subdomains" placeholder="example.com
app.example.com">{{ raw_input }}</textarea><br>
        <button type="submit">Run Analysis</button>
    </form>

    {% if results %}
        <h2>Analysis Results</h2>
        {% for sub, files in results.items() %}
            <div class="card">
                <h3>Target: {{ sub }}</h3>
                {% if not files %}
                    <p>No findings or unreachable.</p>
                {% elif files.error %}
                    <p style="color: #f87171;">{{ files.error }}</p>
                {% else %}
                    {% for fname, cats in files.items() %}
                        <h4>File: <span class="badge">{{ fname }}</span></h4>
                        {% for cat, items in cats.items() %}
                            <strong>{{ cat }}:</strong>
                            <pre>{{ items | join('\n') }}</pre>
                        {% endfor %}
                    {% endfor %}
                {% endif %}
            </div>
        {% endfor %}
    {% endif %}
</body>
</html>
"""

def start_web_ui():
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def index():
        results = None
        raw_input = ""
        if request.method == "POST":
            raw_input = request.form.get("subdomains", "")
            subdomains = [line.strip() for line in raw_input.splitlines() if line.strip()]
            if subdomains:
                results = run_scanner(subdomains)
        return render_template_string(HTML_TEMPLATE, results=results, raw_input=raw_input)

    print("[*] Starting Web UI at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)

# --- ENTRY POINT (CLI VS UI) ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated JS Recon & Static Analysis Tool")
    parser.add_argument("-f", "--file", default="subdomains.txt", help="Path to subdomains file (CLI mode)")
    parser.add_argument("-o", "--output", default="recon_output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--ui", action="store_true", help="Launch the optional local Web UI")
    
    args = parser.parse_args()

    if args.ui:
        start_web_ui()
    else:
        if not os.path.exists(args.file):
            print(f"[!] Error: '{args.file}' not found. Create it or run with --ui.")
        else:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            run_scanner(targets, output_dir=args.output, threads=args.threads)