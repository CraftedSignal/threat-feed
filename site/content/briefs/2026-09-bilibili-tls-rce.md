---
title: Bilibili Desktop TLS Verification Bypass and Remote JavaScript Injection
slug: 2026-09-bilibili-tls-rce
description: Bilibili Desktop versions 1.18.0 and earlier are vulnerable to remote command execution and credential theft due to disabled TLS certificate verification and the execution of unsigned remote JavaScript configurations.
date: "2026-09-05T13:32:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bilibili:bilibili_desktop:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - credential-theft
  - mitm
vendors:
  - Bilibili
products:
  - Bilibili Desktop (<= 1.18.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker ... can execute system commands.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An attacker ... can ... steal login credentials.
    confidence_band: high
cves:
  - id: CVE-2026-86185
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86185
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Bilibili Desktop to a version after 1.18.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-86185 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version
      owner: IT Operations
      addresses: CVE-2026-86185
      evidence: NVD advisory
---

Bilibili Desktop versions through 1.18.0 contain a critical vulnerability where TLS certificate verification is disabled process-wide. This implementation failure allows an attacker in an on-path position to perform Man-in-the-Middle (MitM) attacks by intercepting network traffic and injecting unsigned remote JavaScript configuration files. Because the application fails to perform integrity checks on these configurations, the injected code is executed within the renderer process. The renderer process maintains access to a privileged Inter-Process Communication (IPC) bridge, enabling the attacker to break out of the application sandbox to execute arbitrary system commands or exfiltrate sensitive user credentials. This vulnerability represents a significant risk for users on untrusted networks, as the lack of TLS verification removes the primary defense against traffic interception and malicious payload delivery.

## Impact

The vulnerability allows for full compromise of the Bilibili Desktop client. An attacker can achieve Remote Code Execution (RCE) with the privileges of the local user and steal authentication tokens or login credentials stored by the application. This could lead to account takeover and persistence within the user's local system environment.

## Recommendation

Upgrade Bilibili Desktop to the latest version immediately to ensure TLS certificate verification is enforced and remote configuration integrity is validated. Monitor network logs for unusual certificate mismatches or unauthorized traffic redirection to Bilibili configuration endpoints if the client remains unpatched.
