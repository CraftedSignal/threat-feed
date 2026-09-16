---
title: Arbitrary File Upload and RCE in Pluck CMS via CVE-2023-50564
slug: 2026-09-pluck-rce
description: An authenticated arbitrary file upload vulnerability in Pluck CMS v4.7.18 allows remote attackers to achieve code execution by uploading a malicious ZIP archive via the module installation interface.
date: "2026-09-16T17:57:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pluck-cms:pluck:4.7.18:-:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - file-upload
  - pluck-cms
vendors:
  - Pluck CMS
products:
  - Pluck (4.7.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Arbitrary file upload in Pluck-CMS v4.7.18 via modules_install.php enabling code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Authenticated arbitrary file upload via the installmodule endpoint (ZIP containing PHP payload) leading to RCE.
    confidence_band: high
cves:
  - id: CVE-2023-50564
    cvss: 8.8
    epss: 0.29069
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-THEFIZZYFISH-CVE-2023-50564-PLUCK
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50564
rules:
  - title: Detects CVE-2023-50564 Exploitation - Arbitrary File Upload in Pluck CMS
    description: Detects exploitation attempts against CVE-2023-50564 involving the upload of a ZIP file to the module installation endpoint
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy web server rule to monitor for module installation attempts
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms exploitation vector via admin.php?action=installmodule
  enrichment_needed:
    - item: CVE-2023-50564
      owner: CTI
      reason: Monitor vendor portals for formal patch releases
      evidence: N/A
  hunt_leads:
    - lead: Search logs for POST requests to admin.php?action=installmodule followed by 200 OK responses
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as the entry point for the exploit
  mitigation_plan:
    - priority: immediate
      action: Restrict admin access to trusted IPs
      owner: IT Operations
      addresses: CVE-2023-50564
      evidence: 'Privileges required: LOW, limiting access reduces attack surface'
---

Pluck CMS version 4.7.18 contains an arbitrary file upload vulnerability (CVE-2023-50564) located in the `modules_install.php` component. This vulnerability is reachable by an authenticated user with access to the module installation functionality. By interacting with the `admin.php?action=installmodule` endpoint, an attacker can upload a specially crafted ZIP archive containing a PHP payload. When the system processes the uploaded ZIP file, the included PHP file is saved to the server, allowing the attacker to trigger remote code execution (RCE). As of September 2026, multiple proof-of-concept exploits have been published, significantly lowering the barrier for exploitation. Defenders should restrict access to the administrative dashboard and ensure the instance is patched.

## Attack Chain

1. Attacker performs authentication to obtain a valid session cookie for the Pluck CMS administration interface.
2. Attacker navigates to the module installation page at `admin.php?action=installmodule`.
3. Attacker crafts a ZIP file containing a malicious PHP web shell or payload.
4. Attacker sends an HTTP POST request to the `modules_install.php` script to upload the crafted ZIP file.
5. The server-side code insecurely extracts the ZIP contents to a directory on the web server.
6. The web server extracts the PHP payload file, potentially into a location accessible to the public web root.
7. Attacker navigates to the URL where the uploaded PHP file is stored.
8. Web server executes the PHP payload, granting the attacker arbitrary code execution on the underlying host.

## Impact

Successful exploitation of CVE-2023-50564 results in full remote code execution on the target server. This enables attackers to steal sensitive application data, pivot deeper into the internal network, or deploy additional malware. Given the high CVSS score of 8.8, this flaw poses a critical risk to any infrastructure hosting unpatched versions of Pluck CMS 4.7.18.

## Recommendation

- Patch Pluck CMS instances to the latest available version beyond 4.7.18.
- Implement strict access control lists (ACLs) for the `admin.php` endpoint to prevent unauthorized access by low-privileged users.
- Deploy the provided webserver detection rule to monitor for malicious file upload patterns in application logs.
- Audit the web server's upload directories to identify and remove unauthorized .php or .phtml files.
