# JS Recon & Static Analysis Tool

A lightweight, multi-threaded Python reconnaissance and static analysis tool designed to extract, beautify, and scan JavaScript files from target domains for potential secrets, endpoints, API calls, and configuration keys.

Features a dual-mode interface: run it quickly via the **Command Line (CLI)** or launch the built-in **Web UI** for a clean dashboard view.

---

## Features

- **Multi-Threaded Performance:** Scans multiple subdomains concurrently using Python's `ThreadPoolExecutor`.
- **Inline & External Script Harvesting:** Parses both external `.js` files and inline `<script>` blocks embedded within HTML.
- **Shannon Entropy Filtering:** Reduces false positives by filtering low-entropy strings (e.g., placeholder text or generic variable names) when scanning for credentials.
- **Auto-Beautification:** Automatically cleans and formats minified JavaScript using `jsbeautifier`.
- **Dual Interface:** Switch effortlessly between a traditional CLI tool and a minimal, modern local Web UI powered by Flask.
- **Automated Reporting:** Generates structured JSON data (`report.json`) and human-readable Markdown reports (`report.md`).

---

## Installation

1. Clone the repository:
   
   git clone https://github.com/itzsagar32/Js_analyser
   cd Js_analyser


   2.Install the required dependencies:
    

    pip install -r requirements.txt

Usage
1. Command Line Interface (CLI)

Create a file named subdomains.txt with one target per line, then run:


python js_recon.py -f subdomains.txt -t 10

CLI Options:

    -f, --file: Path to the subdomains file (default: subdomains.txt)

    -o, --output: Output directory for reports and downloaded JS files (default: recon_output)

    -t, --threads: Number of concurrent threads (default: 5)

    --ui: Launch the local Web UI dashboard

2. Local Web UI Dashboard

Launch the interactive web server by passing the --ui flag:


python js_recon.py --ui

Open your browser and navigate to http://127.0.0.1:5000 to paste targets and review findings visually.
Output Structure

When a scan completes, the tool generates an output folder with the following layout:
Plaintext

recon_output/
├── report.json          # Machine-readable structured results
├── report.md            # Clean Markdown summary report
└── target_domain_com/   # Folder per target containing beautified JS files
    ├── script1.js
    └── inline_scripts.js

Disclaimer

This tool is intended for authorized security research, auditing, and educational purposes only. Always ensure you have explicit permission before scanning or probing web applications.