"""Port Scanner & Service Detector — http://localhost:5003"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import concurrent.futures
from flask import Flask, Response, render_template, request, jsonify

MAX_PORTS_PER_SCAN = 1024
DEFAULT_TIMEOUT = 1.0

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]

SCAN_PROFILES = {
    "common": COMMON_PORTS,
    "quick": [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443],
    "web": [80, 443, 8080, 8443, 3000, 5173, 8000, 8888, 9000],
    "database": [3306, 5432, 6379, 27017, 1433, 1521, 9042],
    "remote": [22, 23, 3389, 5900, 5985, 5986, 2222],
}

ALLOWED_WITHOUT_CONSENT = {"127.0.0.1", "localhost", "::1", "scanme.nmap.org"}

SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle",
    3000: "Dev-HTTP", 5173: "Vite", 8000: "HTTP-Alt", 8888: "HTTP-Alt",
}

HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900, 6379, 27017}
MEDIUM_RISK_PORTS = {22, 25, 3306, 5432, 1433, 8080}


def create_app():
    app = Flask(__name__)

    @app.route("/")
    def about():
        return render_template("about.html")

    @app.route("/scan")
    def scan_page():
        return render_template("scan.html")

    @app.route("/api/scan", methods=["POST"])
    def scan_stream():
        data = request.get_json() or {}
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "Target is required"}), 400

        consent = data.get("consent", False)
        if not consent and target.lower() not in ALLOWED_WITHOUT_CONSENT:
            try:
                ip_check = resolve_host(target)
                if ip_check not in ("127.0.0.1", "::1") and target.lower() not in ALLOWED_WITHOUT_CONSENT:
                    return jsonify({
                        "error": "Confirm you have permission to scan this target, or use 127.0.0.1 / scanme.nmap.org",
                    }), 403
            except ValueError as e:
                return jsonify({"error": str(e)}), 400

        try:
            ip = resolve_host(target)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        timeout = min(max(float(data.get("timeout", DEFAULT_TIMEOUT)), 0.3), 5.0)
        scan_type = data.get("scan_type", "connect")
        ping_first = data.get("ping_first", False)
        include_udp = data.get("include_udp", False)
        ports_spec = data.get("ports", "common")

        try:
            ports = parse_ports(ports_spec)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if len(ports) > MAX_PORTS_PER_SCAN:
            return jsonify({"error": f"Max {MAX_PORTS_PER_SCAN} ports per scan. You requested {len(ports)}."}), 400

        def generate():
            start = time.time()
            yield ndjson({"type": "start", "target": target, "ip": ip, "total": len(ports), "scan_type": scan_type})

            if ping_first:
                alive = host_alive(target)
                yield ndjson({"type": "ping", "alive": alive, "message": "Host responded to ping" if alive else "No ping reply (host may still have open ports)"})
                if not alive:
                    yield ndjson({"type": "warn", "message": "Host appears down — continuing scan anyway."})

            open_ports = []
            scanned = 0

            if scan_type == "connect":
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
                    futures = {pool.submit(scan_tcp, ip, p, timeout): p for p in ports}
                    for fut in concurrent.futures.as_completed(futures):
                        scanned += 1
                        result = fut.result()
                        if result:
                            open_ports.append(result)
                            yield ndjson({"type": "found", "port": result})
                        if scanned % 5 == 0 or scanned == len(ports):
                            yield ndjson({
                                "type": "progress",
                                "scanned": scanned,
                                "total": len(ports),
                                "found": len(open_ports),
                                "elapsed": round(time.time() - start, 2),
                            })
            else:
                yield ndjson({"type": "warn", "message": "SYN scan requires raw sockets & admin — running connect scan instead."})
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
                    futures = {pool.submit(scan_tcp, ip, p, timeout): p for p in ports}
                    for fut in concurrent.futures.as_completed(futures):
                        scanned += 1
                        result = fut.result()
                        if result:
                            open_ports.append(result)
                            yield ndjson({"type": "found", "port": result})
                        if scanned % 5 == 0 or scanned == len(ports):
                            yield ndjson({
                                "type": "progress",
                                "scanned": scanned,
                                "total": len(ports),
                                "found": len(open_ports),
                                "elapsed": round(time.time() - start, 2),
                            })

            if include_udp:
                yield ndjson({"type": "udp_start", "port": 53})
                udp_result = scan_udp_dns(ip, timeout)
                if udp_result:
                    open_ports.append(udp_result)
                    yield ndjson({"type": "found", "port": udp_result})

            open_ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "tcp")))
            elapsed = round(time.time() - start, 2)
            yield ndjson({
                "type": "done",
                "target": target,
                "ip": ip,
                "scanned": len(ports) + (1 if include_udp else 0),
                "open": open_ports,
                "elapsed": elapsed,
            })

        return Response(generate(), mimetype="application/x-ndjson")

    return app


app = create_app()


def ndjson(obj):
    return json.dumps(obj) + "\n"


def parse_ports(spec):
    spec = (spec or "common").strip().lower()
    if spec in SCAN_PROFILES:
        return list(SCAN_PROFILES[spec])
    if spec == "1-1024":
        return list(range(1, 1025))
    if spec == "1-100":
        return list(range(1, 101))
    if re.match(r"^\d+-\d+$", spec):
        start, end = map(int, spec.split("-"))
        if start > end or start < 1 or end > 65535:
            raise ValueError("Invalid port range")
        ports = list(range(start, end + 1))
        if len(ports) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"Range too large (max {MAX_PORTS_PER_SCAN} ports)")
        return ports
    if re.match(r"^\d+$", spec):
        p = int(spec)
        if p < 1 or p > 65535:
            raise ValueError("Port must be 1–65535")
        return [p]
    if "," in spec:
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if re.match(r"^\d+-\d+$", part):
                s, e = map(int, part.split("-"))
                ports.extend(range(s, e + 1))
            elif re.match(r"^\d+$", part):
                ports.append(int(part))
            else:
                raise ValueError(f"Invalid port: {part}")
        ports = sorted(set(p for p in ports if 1 <= p <= 65535))
        if not ports:
            raise ValueError("No valid ports")
        if len(ports) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"Too many ports (max {MAX_PORTS_PER_SCAN})")
        return ports
    raise ValueError("Invalid ports. Use profile name, 443, 22,80,443, or 8000-8100")


def resolve_host(target):
    if target.lower() in ("localhost",):
        return "127.0.0.1"
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host: {e}") from e


def host_alive(host):
    try:
        param_count = "-n" if sys.platform == "win32" else "-c"
        param_wait = "-w" if sys.platform == "win32" else "-W"
        wait = "1000" if sys.platform == "win32" else "1"
        result = subprocess.run(
            ["ping", param_count, "1", param_wait, wait, host],
            capture_output=True,
            timeout=3,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def scan_tcp(host, port, timeout):
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return None
            rtt = round((time.perf_counter() - t0) * 1000, 1)
            banner = grab_banner(host, port, timeout)
            service = detect_service(port, banner)
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "banner": banner or "—",
                "rtt_ms": rtt,
                "risk": risk_hint(port, service),
            }
    except (socket.error, OSError):
        return None


def scan_udp_dns(host, timeout=2.0):
    """Minimal DNS query on UDP/53 — educational demo."""
    query = bytes([
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01,
    ])
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (host, 53))
            s.recvfrom(512)
            rtt = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "port": 53,
                "protocol": "udp",
                "state": "open|filtered",
                "service": "DNS (UDP)",
                "banner": "Responded to DNS probe",
                "rtt_ms": rtt,
                "risk": "info",
            }
    except socket.timeout:
        return None
    except (socket.error, OSError):
        return None


def grab_banner(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080, 8000, 8888, 3000, 5173):
                s.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 443 or port == 8443:
                return "TLS (encrypted — Server header not fetched)"
            else:
                s.send(b"\r\n")
            data = s.recv(512).decode("utf-8", errors="replace").strip()
            return data[:200] if data else None
    except (socket.error, OSError, UnicodeDecodeError):
        return None


def detect_service(port, banner):
    base = SERVICE_HINTS.get(port, "unknown")
    if not banner or banner == "—":
        return base
    b = banner.lower()
    if b.startswith("ssh-"):
        ver = banner.split("-")[2] if banner.count("-") >= 2 else ""
        return f"SSH ({ver.split()[0]})" if ver else "SSH"
    if "openssh" in b:
        return "SSH (OpenSSH)"
    if banner.startswith("220") and "ftp" in b:
        return "FTP"
    if "server:" in b:
        for line in banner.split("\r\n"):
            if line.lower().startswith("server:"):
                return f"HTTP ({line.split(':', 1)[1].strip()[:40]})"
    if "mysql" in b:
        return "MySQL"
    if "redis" in b:
        return "Redis"
    if "+ok" in b or "pop3" in b:
        return "POP3"
    if "smtp" in b or banner.startswith("220 "):
        return base if base != "unknown" else "SMTP?"
    return base


def risk_hint(port, service):
    if port in HIGH_RISK_PORTS:
        return "high"
    if port in MEDIUM_RISK_PORTS:
        return "medium"
    if port in (80, 443, 8443):
        return "info"
    s = (service or "").lower()
    if "redis" in s or "mongo" in s or "telnet" in s:
        return "high"
    return "low"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    print(f"Port Scanner -> http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
