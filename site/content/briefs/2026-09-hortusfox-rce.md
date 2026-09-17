---
title: Remote Code Execution in HortusFox-Web via Import/Export
slug: 2026-09-hortusfox-rce
description: HortusFox-Web versions prior to 6.1 are vulnerable to remote code execution allowing authenticated administrators to execute arbitrary OS commands via the Import/Export feature.
date: "2026-09-17T17:59:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hortusfox:hortusfox-web:*:*:*:*:*:*:*:*
vendors:
  - HortusFox
products:
  - HortusFox-Web (< 6.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: HortusFox-Web prior to version 6.1 contains a remote code execution vulnerability that allows authenticated administrators to execute arbitrary OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-92980
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92980
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade HortusFox-Web to version 6.1 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states HortusFox-Web prior to version 6.1 contains the RCE vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 6.1
      owner: IT Operations
      addresses: CVE-2026-92980
      evidence: NVD vulnerability disclosure.
---

HortusFox-Web versions prior to 6.1 contain a remote code execution vulnerability (CVE-2026-92980) that allows authenticated administrators to execute arbitrary OS commands on the underlying host. The vulnerability resides in the application's Import/Export functionality, which is designed for data portability. By injecting malicious payloads into the Import/Export workflow, an authenticated attacker can achieve arbitrary code execution running under the privileges of the web server process. This vulnerability is critical for organizations deploying HortusFox-Web, as it grants full command execution capabilities to any user with administrative access.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary OS commands as the web server user. This could lead to full system compromise of the application server, unauthorized data access, lateral movement within the environment, and persistence mechanism deployment.

## Recommendation

Prioritized actions for detection and remediation teams:

- Update HortusFox-Web to version 6.1 or later immediately to mitigate CVE-2026-92980.
- Audit administrative access logs for the HortusFox-Web application to identify unauthorized or anomalous usage of the Import/Export feature.
- Restrict access to the administrative interface of the application to only authorized personnel and secure networks.
- Monitor for suspicious child processes spawning from the web server service account (e.g., cmd.exe, /bin/bash) which may indicate exploitation of this vulnerability.
