---
title: Unrestricted File Upload Vulnerability in ShopEx ECShop
slug: 2026-09-shopex-ecshop-upload
description: ShopEx ECShop versions up to 2.5.1 contain an unrestricted file upload vulnerability in the check_img_type function that allows unauthenticated remote attackers to upload malicious files via the pack_img argument.
date: "2026-09-01T01:01:41Z"
lastmod: "2026-09-01T01:01:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:shopex:ecshop:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - remote-code-execution
  - file-upload
  - web-vulnerability
  - sql-injection
  - cve-2026-82922
vendors:
  - ShopEx
products:
  - ECShop (<= 2.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation of the argument pack_img can lead to unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-82921
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82921
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82922
rules:
  - title: Detects CVE-2026-82921 Exploitation - Unrestricted File Upload
    description: Detects exploitation of CVE-2026-82921 by identifying POST requests to the vulnerable admin/pack.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
  - title: Detects CVE-2026-82922 Exploitation - SQL Injection in ECShop
    description: Detects attempted SQL injection against the ShopEx ECShop flow_update_cart function by monitoring for suspicious characters in the rec_id query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to /admin/ directory to trusted IP ranges
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated file upload.
  hunt_leads:
    - lead: Search for non-image files created in the ECShop web directory
      technique_id: T1190
      data_needed:
        - File system modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unrestricted file upload vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to admin/pack.php
      owner: IT Operations
      addresses: CVE-2026-82921
      evidence: Vulnerability in admin/pack.php allows remote exploitation.
updates:
  - at: "2026-09-01T01:01:51Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-82922 Exploitation - SQL Injection in ECShop'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82922
---

A vulnerability identified as CVE-2026-82921 affects ShopEx ECShop versions up to 2.5.1. The flaw exists within the check_img_type function located in the admin/pack.php script. An unauthenticated remote attacker can exploit this weakness by manipulating the pack_img parameter to bypass file type validation, allowing for the upload of arbitrary, potentially malicious files to the server. Successful exploitation of this vulnerability can lead to remote code execution (RCE) if the uploaded file is subsequently executed by the web server. Public exploit code for this vulnerability is available, and there is no indication that the vendor has addressed this issue following initial disclosure. Defenders should prioritize restricting access to the administrative directory and monitoring for suspicious file uploads.

## Attack Chain

1. Attacker identifies a target server running an unpatched version of ShopEx ECShop (<= 2.5.1).
2. Attacker performs reconnaissance to locate the admin/pack.php script.
3. Attacker crafts a malicious payload (e.g., a PHP web shell) embedded within an image file structure.
4. Attacker sends a crafted HTTP POST request to the admin/pack.php endpoint.
5. Attacker manipulates the pack_img argument within the request to bypass server-side file type checks in check_img_type.
6. The server saves the malicious file to the web root or an accessible upload directory.
7. Attacker navigates to the uploaded file's URL to trigger code execution on the server.
8. Attacker establishes persistent access or begins data exfiltration.

## Impact

Successful exploitation allows for arbitrary file uploads, which provides a direct path for remote code execution. This can result in complete system compromise, unauthorized data access, and lateral movement within the network. Sectors relying on ECShop for e-commerce operations are at high risk of site defacement, financial data theft, and loss of customer information.

## Recommendation

Prioritized actions for detection engineering and security teams:
- Implement strict ingress filtering for the /admin/ directory to ensure it is not reachable from the public internet.
- Deploy the provided Sigma rule to detect suspicious HTTP requests targeting the admin/pack.php script.
- Monitor web server access logs for anomalous POST requests to admin/pack.php that contain unexpected file extensions or script contents.
- Configure file integrity monitoring on the web server's document root to alert on the creation of new executable files in upload directories.
