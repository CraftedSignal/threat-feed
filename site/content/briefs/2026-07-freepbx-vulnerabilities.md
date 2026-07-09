---
title: FreePBX API and Backup Modules Vulnerabilities Allowing Authenticated RCE and SSH Key Injection
slug: 2026-07-freepbx-vulnerabilities
description: FreePBX has released security advisories to address critical vulnerabilities in its API and Backup modules, affecting FreePBX API (versions prior to 17.0.9) and FreePBX Backup (versions prior to 17.0.11), which include authenticated command injection and arbitrary SSH key injection leading to remote code execution and unauthorized access.
date: "2026-07-09T18:15:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freepbx
  - vulnerability
  - command-injection
  - rce
  - ssh-key-injection
  - voip
  - pbx
  - linux
vendors:
  - FreePBX
products:
  - FreePBX API (FreePBX 17)
  - FreePBX Backup (FreePBX 17)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated API generatedocs Host Command Injection
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Authenticated Arbitrary SSH Key Injection via Backup Module
    confidence_band: high
references:
  - https://cyber.gc.ca/en/alerts-advisories/freepbx-security-advisory-av26-680
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-79rg-3xp6-rqq6
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-24w6-hpg3-rwfg
---

On July 9, 2026, the Canadian Centre for Cyber Security (CCCS) issued an advisory highlighting critical vulnerabilities within FreePBX, specifically impacting its API and Backup modules. These vulnerabilities affect FreePBX API versions prior to 17.0.9 and FreePBX Backup versions prior to 17.0.11. The identified flaws include an authenticated host command injection vulnerability (GHSA-79rg-3xp6-rqq6) within the API's `generatedocs` function and an authenticated arbitrary SSH key injection vulnerability (GHSA-24w6-hpg3-rwfg) via the Backup module. Successful exploitation of these issues allows an authenticated attacker to execute arbitrary commands on the underlying system, gain persistent unauthorized access, or achieve remote code execution. This poses a significant risk to FreePBX deployments, potentially leading to full system compromise, data exfiltration, or service disruption. Defenders must prioritize applying the provided updates to mitigate these threats.

## Attack Chain

1. **Initial Access / Authentication:** An attacker obtains or compromises legitimate credentials for a FreePBX user account, gaining authenticated access to the FreePBX web interface or API.
2. **Exploitation (API Command Injection):** The authenticated attacker crafts a malicious request targeting the vulnerable `generatedocs` function within the FreePBX API, embedding operating system commands.
3. **Command Execution:** The FreePBX API processes the crafted request, leading to the execution of arbitrary commands on the underlying server with the privileges of the FreePBX application.
4. **Alternative Exploitation (SSH Key Injection):** As an alternative, the authenticated attacker navigates to the Backup module and injects an arbitrary SSH public key into a configuration file.
5. **Persistence / Remote Access:** If command injection is used, the attacker establishes persistence (e.g., by creating a cron job, installing a web shell, or modifying system startup scripts). If SSH key injection is used, the attacker immediately gains persistent SSH access to the FreePBX server using the corresponding private key.
6. **Impact:** The attacker achieves remote code execution, gains full control over the FreePBX system, which can be used for further lateral movement, data exfiltration, or to disrupt communication services.

## Impact

The exploitation of these authenticated vulnerabilities can lead to severe consequences for FreePBX users. With arbitrary command execution capabilities, attackers can completely compromise the underlying server, gaining unauthorized access to sensitive call detail records, system configurations, and potentially other interconnected systems. The ability to inject SSH keys allows for persistent unauthorized remote access, enabling long-term surveillance or control. This can result in significant data breaches, disruption of critical communication infrastructure, financial losses, and damage to an organization's reputation. While specific victim counts or targeted sectors are not detailed, any organization using affected FreePBX versions is at risk.

## Recommendation

* Immediately apply the security updates for FreePBX API to version 17.0.9 or later, and for FreePBX Backup to version 17.0.11 or later, as recommended by the FreePBX security advisories referenced in this brief.
* Review access logs and FreePBX audit trails for any suspicious authenticated activity, especially around the API `generatedocs` function or Backup module, after applying the patches.
* Implement strong authentication measures, including multi-factor authentication (MFA), for all FreePBX administrative and user accounts to prevent initial authentication bypass.
* Regularly review and rotate SSH keys on FreePBX servers and ensure that only authorized keys are present.
