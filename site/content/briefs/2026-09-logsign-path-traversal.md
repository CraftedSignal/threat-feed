---
title: Path Traversal Vulnerability in Logsign SIEM
slug: 2026-09-logsign-path-traversal
description: Logsign SIEM versions 6.4.101 through 6.4.116 are vulnerable to a path traversal flaw, CVE-2026-90925, which may allow an unauthenticated attacker to access unauthorized files on the host system.
date: "2026-09-28T16:20:54Z"
lastmod: "2026-09-28T16:21:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:innotim:logsign_siem:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - web-application
vendors:
  - Innotim Software
products:
  - Logsign SIEM (6.4.101 - 6.4.116)
  - Logsign SIEM (6.4.101-6.4.116)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper Control of Generation of Code ('Code Injection') vulnerability in Innotim Software, Telecommunications and Consultancy Trade Ltd. Co. Logsign SIEM allows Code Injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: This flaw allows an attacker to execute arbitrary code within the context of the application.
    confidence_band: high
cves:
  - id: CVE-2026-90925
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90925
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90926
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Logsign SIEM to version 6.4.117
      owner: IT Operations
      due: 48h
      evidence: Source states affected versions 6.4.101 before 6.4.117
  mitigation_plan:
    - priority: immediate
      action: Restrict web interface access to trusted networks
      owner: IT Operations
      addresses: CVE-2026-90925
      evidence: Reduces exposure to unauthenticated exploitation
updates:
  - at: "2026-09-28T16:21:02Z"
    level: L2
    summary: added coverage for Logsign SIEM (6.4.101-6.4.116)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90926
---

Innotim Software's Logsign SIEM product is affected by a path traversal vulnerability identified as CVE-2026-90925. This vulnerability stems from improper validation of user-supplied input when accessing file paths, allowing an attacker to navigate outside of the intended directory structure. The flaw specifically impacts versions 6.4.101 through 6.4.116 of the Logsign SIEM platform. By manipulating file path parameters in HTTP requests, an unauthenticated user could potentially gain unauthorized read access to sensitive files stored on the server, including configuration files, credentials, or system logs. Defenders should prioritize patching affected instances to version 6.4.117 or later to mitigate the risk of information disclosure and potential system compromise.

## Impact

Successful exploitation of this vulnerability allows unauthorized file access on the Logsign SIEM server. Depending on the files accessible, this could lead to the exposure of credentials, environment configurations, and other sensitive data, providing an attacker with sufficient reconnaissance to further compromise the network infrastructure where the SIEM is deployed.

## Recommendation

- Upgrade Logsign SIEM to version 6.4.117 or later immediately to patch CVE-2026-90925.
- Review web server access logs for anomalous requests containing directory traversal sequences (e.g., "../", "..%2f") targeting non-public directories.
- Limit network access to the Logsign SIEM web interface to trusted management networks only, using firewall controls to mitigate potential remote exploitation attempts.
