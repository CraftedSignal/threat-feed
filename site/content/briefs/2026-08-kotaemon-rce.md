---
title: Unauthenticated Remote Code Execution in kotaemon
slug: 2026-08-kotaemon-rce
description: An insecure deserialization vulnerability (CVE-2026-69098) in the kotaemon check_connection endpoint allows unauthenticated attackers to achieve remote code execution by injecting malicious __type__ fields.
date: "2026-08-04T17:25:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Cinnamon
products:
  - kotaemon
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: kotaemon through 0.12.0 contains an insecure deserialization vulnerability in the check_connection endpoint that allows unauthenticated attackers to instantiate arbitrary Python classes.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can exploit this to override the __type__ field with subprocess.check_output and arbitrary arguments, achieving remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-69098
    cvss: 9.8
rules:
  - title: Detect CVE-2026-69098 Exploitation - Insecure Deserialization in kotaemon
    description: Detects potential exploitation attempts of CVE-2026-69098 by identifying POST requests to the check_connection endpoint containing potential deserialization markers like __type__ and shell-like subprocess strings.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade kotaemon to version 0.12.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions through 0.12.0 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the /check_connection endpoint
      owner: IT Operations
      addresses: CVE-2026-69098
      evidence: Vulnerability is in the check_connection endpoint.
---

Cinnamon kotaemon versions through 0.12.0 contain a critical insecure deserialization vulnerability identified as CVE-2026-69098. The vulnerability exists within the application's 'check_connection' endpoint, which fails to properly sanitize user-supplied input when deserializing YAML or JSON data. By crafting a specific payload containing a '__type__' field, an unauthenticated remote attacker can instruct the application to instantiate arbitrary Python classes. 

The exploit allows an attacker to manipulate this type-instantiation mechanism to trigger 'subprocess.check_output' with attacker-supplied arguments. This results in the execution of arbitrary commands with the privileges of the underlying application process. Because the endpoint does not require authentication, the attack vector is highly accessible to any network actor capable of reaching the service. Given the ease of exploitation and the severity of achieving remote code execution, this vulnerability poses a significant risk to any environment hosting kotaemon.

## Impact

Successful exploitation results in full remote code execution on the server running the kotaemon application. An attacker can execute arbitrary OS commands with the permissions of the user running the application process, potentially leading to total system compromise, data exfiltration, or lateral movement within the network.

## Recommendation

* Upgrade the kotaemon application to a version beyond 0.12.0 immediately to mitigate CVE-2026-69098.
* Implement network-level access control to restrict access to the 'check_connection' endpoint to authorized users or internal network segments only.
* Audit application logs for suspicious POST requests directed at the '/check_connection' URI that contain unexpected JSON/YAML structures, particularly those utilizing '__type__' fields or shell-related commands.
* Deploy webserver logging to monitor for unauthorized traffic patterns interacting with API endpoints.
