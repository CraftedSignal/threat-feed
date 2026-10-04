---
title: Unauthenticated Remote Code Execution in Ahsay AhsayCBS
slug: 2026-10-ahsay-cbs-rce
description: Ahsay AhsayCBS up to version 10.3.2 is vulnerable to unauthenticated remote OS command injection via the /rps/api/json/UpdateReceivers.do endpoint, enabling full system compromise.
date: "2026-10-04T09:01:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ahsay:ahsaycbs:*:*:*:*:*:*:*:*
vendors:
  - Ahsay
products:
  - AhsayCBS (< 10.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability affects unknown code of the file /rps/api/json/UpdateReceivers.do of the component Replication Receiver. It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation of the argument random can lead to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-105134
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105134
rules:
  - title: Detects CVE-2026-105134 Exploitation - Unauthenticated RCE via /rps/api/json/UpdateReceivers.do
    description: Detects exploitation attempts against CVE-2026-105134 by identifying suspicious command injection patterns in the 'random' parameter of the UpdateReceivers.do endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade AhsayCBS to 10.3.4
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 10.3.4 is able to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch AhsayCBS to 10.3.4
      owner: IT Operations
      addresses: CVE-2026-105134
      evidence: Upgrading to version 10.3.4 is able to resolve this issue.
---

Ahsay AhsayCBS, a backup software solution, contains a critical security vulnerability (CVE-2026-105134) in the Replication Receiver component. The flaw exists within the /rps/api/json/UpdateReceivers.do endpoint, where the 'random' argument is processed in an insecure manner. An unauthenticated remote attacker can inject arbitrary OS commands by manipulating this argument, leading to complete unauthorized access and execution of code with the privileges of the AhsayCBS application. With a CVSS base score of 10.0, this vulnerability poses a severe risk to organizations using the affected software. Publicly available exploit code has been reported, significantly increasing the likelihood of exploitation. Administrators must upgrade to version 10.3.4 immediately to remediate the vulnerability.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to execute arbitrary system commands, leading to full server compromise, data exfiltration, or deployment of additional malicious payloads such as ransomware. The impact is critical, affecting any environment where AhsayCBS is exposed to the network.

## Recommendation

- Upgrade all instances of AhsayCBS to version 10.3.4 or later immediately.
- Apply the rules below to identify exploitation attempts targeting the identified API endpoint.
- Restrict network access to the AhsayCBS management interface to trusted IP addresses only, especially for the Replication Receiver component.
