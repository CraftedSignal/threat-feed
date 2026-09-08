---
title: Unrestricted File Upload Vulnerability in iWebShop
slug: 2026-09-iwebshop-unrestricted-upload
description: CVE-2026-86666 allows remote, unauthenticated attackers to perform arbitrary file uploads via the uploadFile function in iWebShop-5 versions up to 5.15.
date: "2026-09-08T17:42:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aircheng_org:iwebshop_5:*:*:*:*:*:*:*:*
tags:
  - web-application
  - file-upload
  - vulnerability
vendors:
  - aircheng-org
products:
  - iWebShop-5 (<= 5.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation results in unrestricted upload.
    confidence_band: high
cves:
  - id: CVE-2026-86666
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86666
rules:
  - title: Detect CVE-2026-86666 Exploitation - Unauthorized File Upload Attempt
    description: Detects exploitation attempts targeting the iWebShop uploadFile function by monitoring web traffic to the pic.php controller.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to /controllers/pic.php.
      owner: IT Operations
      due: 24h
      evidence: Source states the attack can be executed remotely.
  mitigation_plan:
    - priority: immediate
      action: Review vendor advisories for a patch addressing CVE-2026-86666.
      owner: IT Operations
      addresses: CVE-2026-86666
      evidence: Vulnerability reported but not yet responded to by project.
---

A high-severity unrestricted file upload vulnerability, identified as CVE-2026-86666, exists in iWebShop-5 versions up to 5.15. The vulnerability is located within the uploadFile function of the controllers/pic.php file. Remote attackers can leverage this flaw to upload malicious files, such as web shells, to the web server, potentially leading to remote code execution. Public exploit code for this vulnerability is currently available, and the vendor has not yet addressed the issue. Organizations using iWebShop-5 are at risk of compromise and should restrict access to the affected upload functionality until a security patch is provided.

## Impact

The vulnerability allows for remote file upload, which is a precursor to full system compromise or web defacement. Because the exploit is publicly available, the risk of automated or targeted exploitation is elevated. Organizations hosting e-commerce platforms using the affected versions of iWebShop are highly susceptible to malicious file drops and subsequent code execution.

## Recommendation

- Implement request filtering at the web application firewall (WAF) to inspect POST requests directed to /controllers/pic.php for suspicious file extensions or content types.
- Monitor web server access logs for anomalous requests to the uploadFile function.
- Disable the affected functionality or restrict access to the /controllers/pic.php endpoint to known administrative source IPs until a vendor patch is released.
