---
title: Remote Code Execution in Omnispace Agora Project via CVE-2026-63146
slug: 2026-10-omnispace-agora-rce
description: Omnispace Agora Project versions prior to 26.10.0 are vulnerable to unauthenticated remote code execution due to chained SQL injection and configuration file injection.
date: "2026-10-13T20:43:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:omnispace:agora_project:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - sql-injection
  - web-application-vulnerability
vendors:
  - Omnispace
products:
  - Agora Project (< 26.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: By leveraging PDO::ATTR_EMULATE_PREPARES with stacked queries, an unauthenticated attacker can re-trigger the installer and inject arbitrary PHP code into the config.inc.php file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can exploit the SQL injection to re-trigger the installer and inject arbitrary PHP code into config.inc.php, achieving unauthenticated remote code execution on the underlying system.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63146
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Agora Project to 26.10.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source states versions before 26.10.0 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 26.10.0
      owner: IT Operations
      addresses: CVE-2026-63146
      evidence: NVD vulnerability disclosure
---

Omnispace Agora Project versions before 26.10.0 contain a critical code injection vulnerability (CVE-2026-63146) that allows unauthenticated remote code execution (RCE). The vulnerability stems from improper sanitization during the application installation process within the File::updateConfigFile() and DbInstall::dbControl() functions. Attackers can leverage an underlying SQL injection vulnerability enabled by PDO::ATTR_EMULATE_PREPARES, which supports stacked queries. By executing stacked SQL queries, an attacker can trigger the re-installation workflow of the application and inject arbitrary PHP code directly into the config.inc.php configuration file. This vulnerability is particularly dangerous as it provides a pathway for an unauthenticated user to achieve full control over the application and the underlying server environment.

## Impact

Successful exploitation results in full remote code execution, granting attackers the ability to run arbitrary system commands, exfiltrate sensitive data, or establish persistence on the host server. The vulnerability carries a CVSS v3.1 base score of 9.8, reflecting the ease of exploitation and the critical nature of the impact. Any server running an affected version of Agora Project is at risk of total compromise.

## Recommendation

Prioritized actions for security and IT operations teams:

- Upgrade all instances of Omnispace Agora Project to version 26.10.0 or later immediately to patch CVE-2026-63146.
- Review the config.inc.php file on all accessible web servers for unauthorized PHP code or unexpected changes.
- Disable PDO::ATTR_EMULATE_PREPARES in database connection configurations if the application logic permits, to mitigate the feasibility of stacked query-based SQL injection.
