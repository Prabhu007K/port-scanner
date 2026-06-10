# Automated Port Scanner & Service Detector

An educational Flask recon tool with an **about page** and **interactive scanner**. Multi-threaded TCP connect scans, live streaming progress, banner grabbing, service detection, risk hints, UDP/DNS demo, and exportable results.

## Live Demo

<!-- Deploy on Render — NOT Netlify/GitHub Pages -->
`https://port-scanner-t4hb.onrender.com`

## Can this deploy on Netlify?

**No.** Like the SQLi lab, this is a **Python Flask app** that runs **server-side socket scans**. Netlify and GitHub Pages only host static files. Use **[Render](https://render.com)** or **[Railway](https://railway.app)** (free tier).

## Features

### About page (`/`)
- What port scanning is and how it works
- Connect scan vs SYN scan comparison
- Legal / ethical guidelines
- Architecture diagram
- Deploy platform note
- **Continue** → scanner

### Interactive scanner (`/scan`)
- **Live progress** — streaming NDJSON, progress bar, elapsed time
- **Scan profiles** — common, quick, web, database, remote access
- **Custom ports** — `443`, `22,80,443`, `8000-8100`
- **Preset targets** — localhost, scanme.nmap.org
- **Consent checkbox** — required for non-demo targets
- **Connect vs SYN** — SYN explained; connect implemented
- **Ping host first** — optional ICMP check
- **UDP/53 DNS probe** — optional demo
- **Adjustable timeout** — 0.5–3 seconds
- **Max 1024 ports** per scan (rate limit)
- **Rich results** — protocol, RTT, risk level, banner
- **Banner parsing** — SSH, HTTP Server, FTP hints
- **Port heatmap** — 1–1024 grid visualization
- **Export** — JSON, CSV, copy table
- **Session history** — last 5 scans (sessionStorage)
- Terminal-style UI with scanline effect

## Tech Stack

- Python 3, Flask
- `socket` — TCP connect + UDP DNS probe
- `concurrent.futures` — threaded scanning
- HTML, CSS, JavaScript (streaming fetch)

## Project Structure

```
├── app.py
├── run.py
├── requirements.txt
├── start.bat
├── templates/
│   ├── about.html
│   └── scan.html
├── static/
│   ├── css/style.css
│   ├── css/about.css
│   └── js/app.js
├── description.txt
└── README.md
```

## Run Locally

```bash
pip install -r requirements.txt
python run.py
```

- **http://localhost:5003** — about page
- **http://localhost:5003/scan** — scanner

Or double-click `start.bat` on Windows.

## Safe demo scan

1. Open **http://localhost:5003/scan**
2. Target: `127.0.0.1` or `scanme.nmap.org`
3. Profile: **Quick**
4. Click **Start scan**

## Deploy on Render (free)

1. Push this folder to GitHub.
2. **New → Web Service** → connect repo.
3. **Build:** `pip install -r requirements.txt`
4. **Start:** `gunicorn app:app --bind 0.0.0.0:$PORT`
5. **Instance:** Free

> **Warning:** Scanning from a cloud server may behave differently than localhost. Only scan permitted targets.

## Deploy on Railway

Same as Render — connect repo, set start command to `gunicorn app:app --bind 0.0.0.0:$PORT`.
