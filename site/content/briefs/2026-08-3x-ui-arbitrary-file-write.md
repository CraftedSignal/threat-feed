---
title: Authenticated Arbitrary File Write in 3x-ui via Xray Log Path Manipulation
slug: 2026-08-3x-ui-arbitrary-file-write
description: An authenticated administrator in 3x-ui can abuse log configuration settings to achieve arbitrary file writes, potentially leading to persistent access or code execution as the Xray process user.
date: "2026-08-24T21:57:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Mhsanaei
products:
  - 3x-ui (v3 <= 3.3.0)
  - 3x-ui (v2 <= 2.9.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Depending on the target file and service privileges, this can be used to obtain code execution and persistent host access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: Xray writes the attacker-controlled content to the specified file, allowing SSH access as the user running Xray.
    confidence_band: high
cves:
  - id: CVE-2026-55477
    cvss: 7.2
    epss: 0.00342
references:
  - https://github.com/advisories/GHSA-jm48-m3rr-9hgg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55477
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade all instances of 3x-ui to v3.3.1
      owner: IT Operations
      due: 24h
      evidence: Fixed in v3.3.1.
  mitigation_plan:
    - priority: immediate
      action: Restrict administrator access to trusted personnel
      owner: IT Operations
      addresses: CVE-2026-55477
      evidence: Until you can update to v3.3.1, restrict panel administrator access to fully trusted operators.
---

The 3x-ui panel is vulnerable to an arbitrary file write vulnerability, tracked as CVE-2026-55477, which allows an authenticated administrator to manipulate the system configuration. By modifying the `xrayTemplateConfig.log.access` setting - either through the database import functionality or the built-in raw Xray configuration editor - an attacker can redirect Xray's access logs to an arbitrary file path on the host filesystem. 

When a connection is processed, content injected into an inbound client's 'email' field is written to the configured log destination. Because this allows writing to sensitive system files (such as `.ssh/authorized_keys` or configuration files), an attacker with administrative access to the panel can achieve code execution or gain persistent access, inheriting the privileges of the user running the Xray process. If Xray is deployed with root privileges, this results in full host compromise. The vulnerability is addressed in version 3.3.1, which confines log paths to the application's log directory.

## Attack Chain

1. Attacker authenticates to the 3x-ui web panel as an administrator.
2. Attacker accesses the raw configuration editor or prepares a modified SQLite database file for import.
3. Attacker modifies the `xrayTemplateConfig.log.access` parameter to target a sensitive system file (e.g., `/root/.ssh/authorized_keys`).
4. Attacker creates or modifies an inbound client configuration, setting the 'email' field to contain a malicious payload (e.g., an SSH public key).
5. Attacker saves the configuration or imports the malicious database into the 3x-ui panel.
6. Attacker triggers an inbound connection to the panel through the modified client configuration.
7. The Xray process processes the connection and writes the malicious payload from the 'email' field into the target file.
8. Attacker leverages the modified system file to gain shell access or achieve persistent code execution on the host.

## Impact

The vulnerability allows any authenticated administrator to overwrite or create files with the privileges of the Xray process. Successful exploitation can result in full host compromise, particularly in deployments where Xray runs with elevated (root) privileges. This affects all 3x-ui instances running versions 3.3.0 and earlier (v3 branch) or 2.9.4 and earlier (v2 branch).

## Recommendation

- Upgrade 3x-ui to version 3.3.1 or later immediately to apply path confinement.
- Audit administrative access to the 3x-ui panel; ensure only highly trusted users possess administrative privileges.
- Review filesystem permissions to ensure the Xray process runs with the least privilege necessary, preventing it from writing to sensitive directories outside of its own log folder.
- Monitor logs for unauthorized or unexpected modifications to sensitive files such as `.ssh/authorized_keys` or system cron directories.
