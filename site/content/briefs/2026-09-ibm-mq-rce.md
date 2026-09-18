---
title: IBM MQ Java and JMS Client Deserialization Vulnerability
slug: 2026-09-ibm-mq-rce
description: An authenticated attacker can execute arbitrary code on client applications by exploiting a deserialization filter bypass in IBM MQ Java and JMS client libraries.
date: "2026-09-18T18:07:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:mq:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - IBM MQ (Java and JMS client libraries)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: An authenticated attacker can exploit this flaw to achieve arbitrary code execution on client applications utilizing the affected libraries.
    confidence_band: high
cves:
  - id: CVE-2026-10751
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10751
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Inventory all applications using IBM MQ client libraries to determine exposure.
      owner: AppSec
      due: 48h
      evidence: CVE-2026-10751
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM MQ client libraries to the patched version once released by IBM.
      owner: IT Operations
      addresses: CVE-2026-10751
      evidence: NVD vulnerability mitigation guidance
---

IBM MQ Java and JMS client libraries are susceptible to a critical deserialization filter bypass vulnerability (CVE-2026-10751). The flaw exists within the exception handling mechanism of the libraries. An authenticated attacker who can influence the data processed by a client application using these libraries can trigger this vulnerability to execute arbitrary code. Because the issue resides in the client-side library, any Java application integrating these libraries is potentially at risk if it processes untrusted or attacker-controlled MQ messages. The vulnerability is assigned a CVSS v3.1 score of 7.5, reflecting the risk posed by the ability to achieve remote code execution in the context of the application process. Organizations using IBM MQ client libraries should assess their dependency tree and apply vendor-supplied patches to mitigate the risk of arbitrary code execution.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary code on the host running the vulnerable IBM MQ client application. This can lead to full compromise of the application context, potentially resulting in data exfiltration, lateral movement within the network, or the installation of persistent malicious payloads. The scope of impact is dependent on the privileges of the application process utilizing the library.

## Recommendation

* Identify all Java applications utilizing vulnerable versions of IBM MQ Java and JMS client libraries.
* Consult IBM security bulletins to obtain and apply the latest security patches for the IBM MQ client libraries.
* Implement strict input validation and deserialization filters for all incoming MQ messages to prevent processing of malicious serialized objects.
* Monitor for unexpected process creation or unusual network activity originating from Java applications acting as IBM MQ clients.
