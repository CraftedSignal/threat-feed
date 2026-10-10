---
title: Unauthenticated Remote Code Execution in i-doit Pro via Weak Admin Credentials
slug: 2026-10-idoit-rce
description: A vulnerability in i-doit Pro (versions 25 and below) allows attackers to perform brute-force attacks on the admin-center, enabling the upload of malicious plugins to achieve remote code execution.
date: "2026-10-10T06:53:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:i-doit:i-doit:*:*:*:*:open:*:*:*
  - cpe:2.3:a:i-doit:i-doit:*:*:*:*:pro:*:*:*
tags:
  - remote-code-execution
  - brute-force
  - web-application-vulnerability
vendors:
  - synetics GmbH
products:
  - i-doit Pro (<= 25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: This allows a злоумышленнику easily to pick up a password by method of brute force or guessing to gain access to admin-center.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: These vulnerabilities allow a злоумышленнику to easily pick up a password to get access to admin-center and upload a malicious plugin for remote execution of code.
    confidence_band: high
cves:
  - id: CVE-2023-37756
    cvss: 9.8
    epss: 0.01449
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LEEKENGHWA-CVE-2023-37756-CWE-521-LEAD-TO-MALICIOUS-PLUGIN-UPLOAD-IN-THE-I-DOIT-PRO-25-AND-BELOW
rules:
  - title: Detect i-doit Pro Admin-Center Brute Force Attempt
    description: Detects multiple failed login attempts to the i-doit Pro admin-center interface, which may indicate a brute-force attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to i-doit Pro admin-center to authorized management IP ranges
      owner: IT Operations
      due: 24h
      evidence: Weak password requirements in the admin-center enable brute force
  mitigation_plan:
    - priority: immediate
      action: Upgrade i-doit Pro to a version beyond 25, or implement strict password complexity policy
      owner: IT Operations
      addresses: CVE-2023-37756
      evidence: 'Affected versions: i-doit <= 25'
---

i-doit Pro versions 25 and below contain a critical vulnerability (CVE-2023-37756) stemming from weak password complexity requirements in the admin-center interface. By default, or through administrative misconfiguration, the system allows for trivial passwords, enabling attackers to perform brute-force attacks against the 'admin' account. Once unauthorized access to the admin-center is obtained, an attacker can leverage the plugin management functionality to upload a backdoored archive. By modifying the 'init.php' file within a legitimate plugin archive to include arbitrary system commands, an attacker can achieve remote code execution (RCE) with the privileges of the web server process. The payload executes when an administrator or user activates the compromised plugin, posing a significant risk to the integrity and confidentiality of the CMDB data managed by i-doit Pro.

## Attack Chain

1. An attacker identifies an internet-facing i-doit Pro admin-center interface.
2. The attacker initiates a brute-force or credential-guessing attack against the default 'admin' account due to lack of enforced password complexity.
3. Upon successful authentication, the attacker navigates to the 'Add-on' section within the admin-center.
4. The attacker uploads a legitimate plugin archive and extracts the contents locally.
5. The attacker modifies the 'init.php' file within the plugin to include a reverse shell or other arbitrary command execution payload, ensuring the process is backgrounded to prevent application crashes.
6. The attacker re-archives the modified plugin folder as a ZIP file.
7. The attacker uploads the malicious plugin via the 'Upload' function in the admin-center.
8. The attacker activates the plugin; the payload executes when the system processes the 'init.php' file, resulting in remote code execution.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative control over the i-doit Pro environment. This results in potential unauthorized access to sensitive IT infrastructure documentation, full system compromise, and the ability to execute arbitrary code on the underlying web server, likely leading to data exfiltration or lateral movement within the network.

## Recommendation

1. Immediately restrict access to the i-doit Pro admin-center to trusted management networks using firewall rules.
2. Enforce strong password complexity policies for all administrative accounts, specifically targeting the 'admin' account, as the default configuration may permit trivial passwords.
3. Audit existing plugins for unauthorized modifications by verifying the file integrity of 'init.php' and other executable components against known-good baselines.
4. Monitor web server logs for suspicious POST requests to the plugin upload endpoint and repeated failed login attempts to the admin-center.
