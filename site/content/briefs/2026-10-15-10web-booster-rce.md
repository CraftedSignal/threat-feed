---
title: Arbitrary File Upload in 10Web Booster WordPress Plugin (CVE-2026-108587)
slug: 2026-10-15-10web-booster-rce
description: An unauthenticated remote code execution vulnerability exists in 10Web Booster versions 2.34.10 and earlier due to insecure file handling and nonce leakage.
date: "2026-10-15T06:35:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:10web:booster:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - remote-code-execution
  - cve-2026-108587
vendors:
  - 10Web
products:
  - 10Web Booster (<= 2.34.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-108587
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108587
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade 10Web Booster plugin to version > 2.34.10
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108587 advisory
  mitigation_plan:
    - priority: immediate
      action: Remove world-readable files containing the tenwebio_rest nonce from wp-content/uploads/
      owner: IT Operations
      addresses: CVE-2026-108587
      evidence: Source describes nonce exposure via world-readable files
---

The 10Web Booster plugin for WordPress (versions 2.34.10 and earlier) contains a critical arbitrary file upload vulnerability (CVE-2026-108587) within its `compressCustom` function. This flaw arises from insufficient file type validation and extension filtering on the `page_id` parameter. The vulnerability is chained with an authentication bypass facilitated by a publicly accessible, world-readable nonce (`tenwebio_rest`). This nonce is generated during bulk optimization batches in a cron/loopback context with a user ID of 0, resulting in it being exposed within files in the `wp-content/uploads/` directory. By obtaining this nonce, unauthenticated attackers can interact with the vulnerable REST endpoint to upload malicious, potentially executable files to the web server, leading to full remote code execution. This poses a severe risk to any WordPress environment running the affected plugin versions.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary code on the underlying web server. Given the nature of WordPress plugins, this could lead to full site compromise, unauthorized data exfiltration, and the establishment of persistent backdoors. The ubiquity of WordPress plugins makes this a significant risk for the large volume of websites utilizing the 10Web Booster for performance optimization.

## Recommendation

Prioritized actions for security teams:
- Update the 10Web Booster plugin to the latest available version (beyond 2.34.10) where the fix is implemented.
- Audit the `wp-content/uploads/` directory for any world-readable files containing the `tenwebio_rest` nonce or other sensitive configuration parameters.
- Monitor web server access logs for anomalous `POST` requests to REST API endpoints associated with the 10Web Booster, specifically targeting the `compressCustom` function or suspicious file uploads.
- Review file system permissions in `wp-content/uploads/` to ensure files are not inadvertently set to world-readable if they contain application secrets.
