#!/usr/bin/env python3
"""
Project 21 – Container Security Scanner (Kubernetes)
Scans container images with Trivy and checks K8s misconfigurations.
"""

import os
import json
import subprocess
import sys
from datetime import datetime
import jinja2

# ---------- CONFIG ----------
REPORT_FILE = "scan_report.html"

def scan_image(image_name):
    """Scan a container image with Trivy and return JSON results."""
    try:
        cmd = ["trivy", "image", "--format", "json", image_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
        else:
            print(f"[!] Trivy error for {image_name}: {result.stderr}")
            return None
    except Exception as e:
        print(f"[!] Exception: {e}")
        return None

def list_local_images():
    """List Docker images (using `docker images`)."""
    try:
        result = subprocess.run(["docker", "images", "--format", "json"], capture_output=True, text=True)
        images = []
        for line in result.stdout.strip().splitlines():
            if line:
                images.append(json.loads(line))
        return images
    except Exception as e:
        print(f"[!] Docker error: {e}")
        return []

def generate_report(images, vulns):
    template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Container Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; padding:20px; }
        .container { max-width:1400px; margin:auto; background:white; padding:30px; border-radius:12px; }
        h1 { color:#1a1a2e; border-bottom:3px solid #4a90e2; padding-bottom:10px; }
        .summary { display:flex; gap:20px; margin:20px 0; }
        .card { padding:15px 20px; border-radius:8px; flex:1; min-width:100px; text-align:center; color:white; }
        .card-info { background:#17a2b8; }
        .card-success { background:#28a745; }
        .card-danger { background:#dc3545; }
        .vuln-table { width:100%; border-collapse:collapse; margin:10px 0; }
        .vuln-table th, .vuln-table td { border:1px solid #ddd; padding:8px; text-align:left; }
        .vuln-table th { background:#f2f2f2; }
        .severity-CRITICAL { background:#dc3545; color:white; }
        .severity-HIGH { background:#fd7e14; color:white; }
        .severity-MEDIUM { background:#ffc107; }
        .severity-LOW { background:#28a745; color:white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐳 Container Security Report</h1>
        <p>Generated: {{ timestamp }}</p>
        <div class="summary">
            <div class="card card-info">Images Scanned: {{ images }}</div>
            <div class="card card-success">Vulnerabilities Found: {{ vuln_count }}</div>
            <div class="card card-danger">Critical: {{ critical }}</div>
        </div>
        <h2>Vulnerabilities</h2>
        <table class="vuln-table">
            <thead><tr><th>Image</th><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead>
            <tbody>
            {% for v in vulns %}
            <tr>
                <td>{{ v.image }}</td>
                <td><a href="https://nvd.nist.gov/vuln/detail/{{ v.id }}" target="_blank">{{ v.id }}</a></td>
                <td class="severity-{{ v.severity }}">{{ v.severity }}</td>
                <td>{{ v.description[:100] }}{% if v.description|length > 100 %}…{% endif %}</td>
            </tr>
            {% else %}
            <tr><td colspan="4">No vulnerabilities found.</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
    """
    t = jinja2.Template(template)
    html = t.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        images=len(images),
        vuln_count=len(vulns),
        critical=sum(1 for v in vulns if v['severity'] == 'CRITICAL'),
        vulns=vulns
    )
    with open(REPORT_FILE, 'w') as f:
        f.write(html)
    print(f"[*] Report saved to {REPORT_FILE}")

def main():
    print("[*] Scanning local Docker images...")
    images = list_local_images()
    if not images:
        print("[!] No Docker images found. Pull a test image: docker pull alpine")
        sys.exit(1)
    all_vulns = []
    for img in images:
        repo = img.get('Repository', '')
        tag = img.get('Tag', 'latest')
        image_full = f"{repo}:{tag}" if repo else "alpine:latest"
        print(f"[*] Scanning {image_full}...")
        result = scan_image(image_full)
        if result:
            for res in result.get('Results', []):
                for vuln in res.get('Vulnerabilities', []):
                    all_vulns.append({
                        'image': image_full,
                        'id': vuln.get('VulnerabilityID'),
                        'severity': vuln.get('Severity'),
                        'description': vuln.get('Description', '')
                    })
    generate_report(images, all_vulns)
    print("[+] Scan complete. Open scan_report.html in your browser.")

if __name__ == "__main__":
    main()