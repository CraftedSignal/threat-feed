---
title: OS Command Injection in @mborne/extract
slug: 2026-10-mborne-extract-rce
description: The @mborne/extract library before version 0.2.1 is vulnerable to OS command injection via unsanitized archivePath or targetDir inputs passed to shelljs exec().
date: "2026-10-14T16:33:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mborne:extract:*:*:*:*:*:node.js:*:*
vendors:
  - mborne
products:
  - '@mborne/extract (< 0.2.1)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers controlling these values passed to extract() can inject commands into unquoted shelljs exec() strings in the unzip, 7z, tar-bz2 and gz extractors.
    confidence_band: high
cves:
  - id: CVE-2026-110639
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110639
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @mborne/extract to 0.2.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110639 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade @mborne/extract to 0.2.1 or later
      owner: IT Operations
      addresses: CVE-2026-110639
      evidence: NVD vulnerability details
---

The @mborne/extract Node.js library contains an OS command injection vulnerability, identified as CVE-2026-110639, affecting all versions prior to 0.2.1. The vulnerability stems from improper input validation when handling the 'archivePath' or 'targetDir' options. These parameters are passed directly into 'shelljs.exec()' calls within the library's internal extractors (unzip, 7z, tar-bz2, and gz) without sufficient sanitization. 

If a downstream application accepts user-supplied input and passes it into the extract() function, an attacker can supply shell metacharacters to escape the intended command context and execute arbitrary system commands. Because these processes run with the privileges of the underlying Node.js application, this vulnerability poses a significant risk for remote code execution (RCE) in any environment utilizing vulnerable versions of the package.

## Impact

Successful exploitation allows for arbitrary command execution on the host system running the Node.js application. This potentially leads to full system compromise, data exfiltration, or lateral movement within the network, depending on the permissions of the user account running the Node.js process. The CVSS v3.1 base score is 9.8, reflecting the high potential for total system compromise without authentication.

## Recommendation

- Upgrade the @mborne/extract library to version 0.2.1 or later immediately.
- Review all application code paths where user-supplied input is passed to the extract() function to ensure no untrusted content can influence file paths.
- Apply the principle of least privilege by running the Node.js service account with the minimum necessary filesystem and shell access permissions.
