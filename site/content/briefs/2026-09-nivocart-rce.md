---
title: Arbitrary File Upload Vulnerability in NivoCart File Manager
slug: 2026-09-nivocart-rce
description: NivoCart versions 2.4.0 and earlier are vulnerable to remote code execution via an arbitrary file upload flaw in the File Manager multi() endpoint.
date: "2026-09-20T12:21:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nivocart:nivocart:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - file-upload
  - cve-2026-94104
vendors:
  - NivoCart
products:
  - NivoCart (<= 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers with view-only back-office access can upload PHP files to the web-accessible image/data/ directory and execute them for remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-94104
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94104
rules:
  - title: Detect CVE-2026-94104 Exploitation - Arbitrary File Upload in NivoCart
    description: Detects exploitation of CVE-2026-94104 by monitoring for POST requests to the File Manager multi() endpoint with a chunks parameter greater than 1.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review access logs for POST requests to File Manager endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-94104 exploitation detail
  mitigation_plan:
    - priority: immediate
      action: Restrict back-office access via IP allowlisting or VPN
      owner: IT Operations
      addresses: CVE-2026-94104
      evidence: Vulnerability requires back-office access
---

NivoCart versions 2.4.0 and earlier contain a critical arbitrary file upload vulnerability within the File Manager multi() endpoint. The application fails to validate file extensions during the upload process, particularly when the chunks parameter is set to 2 or higher. This security defect allows an attacker, even one with limited view-only back-office privileges, to bypass intended restrictions and upload malicious PHP scripts to the web-accessible image/data/ directory. Once the file is uploaded, the attacker can execute the script by directly navigating to the file path through a web browser, resulting in full remote code execution on the underlying server. This vulnerability presents a significant risk to NivoCart installations as it grants attackers the ability to compromise server-side operations and data.

## Attack Chain

1. Attacker gains unauthorized or low-privileged access to the NivoCart back-office panel.
2. Attacker navigates to the File Manager component.
3. Attacker initiates an upload request to the multi() endpoint.
4. Attacker manipulates the request to set the chunks parameter to a value of 2 or higher.
5. Attacker uploads a malicious PHP file, bypassing extension validation checks.
6. The application saves the malicious file into the web-accessible image/data/ directory.
7. Attacker requests the uploaded file directly via a web browser to execute the payload.
8. Web server processes the PHP code, granting the attacker remote code execution.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated or low-privileged attacker to achieve remote code execution on the target server. This could lead to a full system compromise, data theft, unauthorized modification of site content, and potential lateral movement within the network. All NivoCart installations at or below version 2.4.0 are affected.

## Recommendation

1. Immediately restrict access to the NivoCart back-office panel to authorized personnel only to mitigate the impact of the required low-level access.
2. Monitor web server access logs for anomalous POST requests to the File Manager multi() endpoint, specifically tracking requests containing the chunks parameter.
3. Implement egress filtering on the web server to prevent post-exploitation activity such as reverse shells or data exfiltration.
4. Periodically audit the image/data/ directory for unauthorized script files (e.g., .php files) that should not be present in an image storage folder.
5. Upgrade NivoCart to a version beyond 2.4.0 once the vendor provides a patch to address the underlying validation flaw in the File Manager.
