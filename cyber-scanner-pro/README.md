# Cyber Scanner Pro

A sleek, terminal-aesthetic network security scanner dashboard built with vanilla HTML, CSS, and JavaScript. Designed as an educational demonstration tool — no real network requests are made.

![Cyber Scanner Pro](https://img.shields.io/badge/status-demo-green) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Multi-phase scan simulation** with animated progress stages
- **Vulnerability findings** with real CVE references (Log4Shell, Heartbleed, and more)
- **Port discovery table** with service fingerprinting display
- **Live scan log** with timestamped events
- **Risk score ring** with animated breakdown bars
- **Export report** as a plain-text `.txt` file
- **Responsive** — works on desktop and mobile
- Zero dependencies · no build step · pure HTML/CSS/JS

## Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/cyber-scanner-pro.git
cd cyber-scanner-pro
# open index.html in your browser — that's it
```

Or simply open `index.html` directly in any modern browser.

## Project Structure

```
cyber-scanner-pro/
├── index.html    # markup & layout
├── style.css     # all styles (dark terminal theme)
├── scanner.js    # scan logic, data, UI interactions
└── README.md
```

## Usage

1. Enter an IP address or hostname in the target field
2. Toggle the scan modules you want (Port Scan, Vuln Check, SSL Audit, etc.)
3. Click **SCAN**
4. Switch between the **Overview**, **Vulnerabilities**, **Ports**, and **Log** tabs
5. Click **↓ EXPORT REPORT** to download a `.txt` summary

## Disclaimer

> This tool is a **front-end simulation** for educational purposes only. It does not perform any real network scanning, does not send any packets, and does not connect to any external hosts. All findings and port data are simulated. Only use real security scanning tools on systems you own or have explicit permission to test.

## License

MIT — see [LICENSE](LICENSE) for details.
