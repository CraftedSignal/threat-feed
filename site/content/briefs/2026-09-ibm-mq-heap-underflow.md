---
title: Heap Buffer Underflow in IBM MQ for HPE NonStop
slug: 2026-09-ibm-mq-heap-underflow
description: IBM MQ for HPE NonStop versions 8.1.0 through 8.1.0.40 contain a heap buffer underflow vulnerability in multi-segment message processing that allows authenticated attackers to execute arbitrary code or trigger denial of service.
date: "2026-09-18T18:06:54Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:ibm:mq:8.1.0:*:*:*:*:hpe_nonstop:*:*
tags:
  - vulnerability
  - remote-code-execution
  - ibm-mq
  - critical
vendors:
  - IBM
products:
  - IBM MQ for HPE NonStop (8.1.0 through 8.1.0.40)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker can exploit this vulnerability to trigger a denial of service or potentially execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-10858
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10858
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all IBM MQ for HPE NonStop installations to identify versions 8.1.0-8.1.0.40.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-10858 scope
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM MQ for HPE NonStop to the latest version as provided by IBM to remediate CVE-2026-10858.
      owner: IT Operations
      addresses: CVE-2026-10858
      evidence: Vulnerability remediation requirement
---

IBM has disclosed a critical vulnerability, CVE-2026-10858, affecting IBM MQ for HPE NonStop versions 8.1.0 through 8.1.0.40. The vulnerability stems from an improper handling of multi-segment messages, resulting in a heap buffer underflow condition. An authenticated attacker can exploit this flaw to crash the message queue manager, causing a denial of service, or potentially gain arbitrary code execution capabilities with the privileges of the IBM MQ service. Given the high CVSS base score of 9.9 and the potential for remote code execution, this represents a significant risk to the integrity and availability of messaging infrastructure. Defenders should prioritize patching or applying vendor-recommended mitigations to affected NonStop environments.

## Impact

The vulnerability poses a severe risk to messaging infrastructure relying on IBM MQ for HPE NonStop. Successful exploitation can lead to total loss of service through application crashes or unauthorized system access. Given that the impact includes potential arbitrary code execution, attackers could leverage this access for internal lateral movement, exfiltration of sensitive queued message data, or further compromise of the HPE NonStop operating environment.

## Recommendation

- Identify all instances of IBM MQ for HPE NonStop within the environment that are running version 8.1.0 through 8.1.0.40.
- Patch affected instances immediately following vendor guidance for CVE-2026-10858.
- Review access control lists (ACLs) for IBM MQ queues to restrict the number of users capable of submitting multi-segment messages, reducing the attack surface until patches are applied.
