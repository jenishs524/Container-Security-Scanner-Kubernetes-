📁 Container Security Scanner (Kubernetes)

Description
Scans container images for vulnerabilities using Trivy and checks Kubernetes misconfigurations (optional). Generates an HTML report.

Key Features

    Lists local Docker images.

    Runs trivy image for each image.

    Parses JSON output for CVEs.

    Generates a report with severity breakdown.

    Optionally checks Kubernetes manifests (extendable).

Technologies

    Trivy, Docker SDK, Kubernetes API (optional), Jinja2.

Prerequisites

    Docker, Trivy installed.

    Python 3, Docker SDK, Jinja2.

Installation
bash

sudo apt install trivy
pip install docker kubernetes jinja2

Usage
bash

python k8s_scanner.py

Sample Output
text

[*] Scanning alpine:latest...
[*] Report saved to scan_report.html

Open scan_report.html to view vulnerabilities.
