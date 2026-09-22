---
title: Path Traversal Vulnerability in Siemens SIMOVE and SIPLANT
slug: 2026-09-siemens-path-traversal
description: An unauthenticated path traversal vulnerability (CVE-2026-67367) in Siemens SIMOVE Fleetmanager and SIPLANT allows remote attackers to read arbitrary files from the underlying operating system.
date: "2026-09-22T16:47:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-67367
  - path-traversal
  - industrial-security
  - siemens
vendors:
  - Siemens
products:
  - SIMOVE Fleetmanager (< 3.1.13, 3.2.4, 3.3.2, 4.0.1)
  - SIPLANT (< 3.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This could allow an unauthenticated remote attacker to read arbitrary files from the underlying operating system without any credentials.
    confidence_band: high
cves:
  - id: CVE-2026-67367
    cvss: 8.6
    epss: 0.00811
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-07
  - https://cert-portal.siemens.com/productcert/html/ssa-517424.html
  - https://www.cve.org/CVERecord?id=CVE-2026-67367
rules:
  - title: Detect CVE-2026-67367 Exploitation - Directory Traversal in HTTP Requests
    description: Detects potential directory traversal attempts via HTTP GET requests targeting embedded web servers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected SIMOVE and SIPLANT instances to recommended versions.
      owner: IT Operations
      due: 48h
      evidence: Vendor remediation instructions.
  hunt_leads:
    - lead: Search logs for unusual file access patterns on industrial control system management interfaces.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-67367 vulnerability in file-serving endpoint.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to management interfaces using firewalls.
      owner: Network Security
      addresses: CVE-2026-67367
      evidence: CISA recommended practices.
---

Siemens has disclosed a critical path traversal vulnerability, identified as CVE-2026-67367, affecting multiple versions of SIMOVE Fleetmanager and SIPLANT. The vulnerability exists within the file-serving endpoint of the products' embedded HTTP server, which fails to properly validate and neutralize directory traversal sequences. This weakness allows an unauthenticated, remote attacker to traverse the file system and access arbitrary files located outside of the intended directory scope on the host operating system. Successful exploitation could lead to the unauthorized disclosure of sensitive information, including configuration secrets, private cryptographic keys, and credential stores. This vulnerability is particularly critical given the products' deployment in the Critical Manufacturing sector. Siemens has released patches for the affected versions and recommends that users update their systems to the latest available releases immediately.

## Impact

The vulnerability poses a high risk to operational security within the Critical Manufacturing sector. Successful exploitation allows an unauthenticated remote attacker to gain unauthorized access to sensitive files on the host system. The exposure of credential stores, private keys, and configuration secrets could facilitate further lateral movement, persistent access, or compromise of connected industrial control systems.

## Recommendation

- Upgrade SIMOVE Fleetmanager and SIPLANT to the versions identified as patched by Siemens (e.g., V3.1.13, V3.2.4, V3.3.2, V4.0.1, or V3.1.4 respectively).
- Implement strict network segmentation to ensure these devices are not accessible from the public internet.
- Utilize VPNs for secure remote access if necessary, ensuring the VPN infrastructure itself is patched and monitored.
- Apply the principle of least privilege by configuring user management to restrict service-level access rights to project files.
- Monitor logs for HTTP requests containing directory traversal patterns (e.g., ../, ..\, /etc/passwd) targeting embedded web servers in OT environments.
