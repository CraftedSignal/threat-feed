---
title: Heap Buffer Overflow in IBM MQ via Malformed Distribution Headers
slug: 2026-09-ibm-mq-overflow
description: IBM MQ is vulnerable to a heap-based buffer overflow during the processing of MQPUT operations, allowing an authenticated attacker to execute a denial of service or escalate privileges.
date: "2026-09-18T18:07:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:mq:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ibm-mq
  - buffer-overflow
vendors:
  - IBM
products:
  - MQ
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM MQ could allow an authenticated attacker to cause a denial of service or potentially escalate privileges due to a heap buffer overflow
    confidence_band: high
cves:
  - id: CVE-2026-10575
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10575
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all IBM MQ instances and apply patches identified in the forthcoming IBM security bulletin for CVE-2026-10575
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-10575 vulnerability identification
  mitigation_plan:
    - priority: immediate
      action: Review and harden MQ security profiles to ensure only authorized users have MQPUT permissions
      owner: Security Operations
      addresses: CVE-2026-10575
      evidence: Authenticated attacker requirement for exploitation
---

IBM MQ is susceptible to a heap-based buffer overflow vulnerability, tracked as CVE-2026-10575, which occurs when the application processes malformed distribution headers during MQPUT operations. This flaw can be triggered by an authenticated attacker who has the ability to send specifically crafted messages to the message queue manager. Successful exploitation of this vulnerability results in either a denial of service (DoS) caused by an application crash or potentially the escalation of privileges within the security context of the affected service. Given the role of IBM MQ in enterprise middleware, this vulnerability poses a significant risk to the availability and integrity of messaging infrastructures. Organizations should review their IBM MQ configurations and apply relevant security updates provided by IBM to mitigate the risk of exploitation.

## Impact

Successful exploitation of CVE-2026-10575 allows an authenticated attacker to disrupt messaging services, impacting critical business processes that rely on MQ for inter-application communication. Furthermore, the potential for privilege escalation could allow an attacker to gain unauthorized control over the queue manager or associated system resources, leading to potential data compromise or further lateral movement within the enterprise environment.

## Recommendation

Prioritize the identification and patching of all IBM MQ instances within the environment. Consult the official IBM security bulletins associated with CVE-2026-10575 to identify the specific patched versions for your deployed MQ release. Restrict the ability of users to send messages to queues that do not require such access, adhering to the principle of least privilege for all MQ service users.
