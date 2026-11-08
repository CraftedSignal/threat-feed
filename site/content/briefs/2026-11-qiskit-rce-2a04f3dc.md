---
brief_id: brief-2026-11-08-qiskit-rce-2a04f3dc
event_id: brief-2026-11-08-qiskit-rce-2a04f3dc
revision: 1
activity_at: "2026-11-08T21:26:38Z"
title: 'IBM Qiskit SDK: Arbitrary code execution via deserialization (CVE-2026-116499)'
slug: 2026-11-qiskit-rce-2a04f3dc
description: IBM Qiskit SDK versions 1.4.2 through 2.6.2 contain a deserialization vulnerability that allows a local attacker to execute arbitrary code within the host environment.
date: "2026-11-08T21:26:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:qiskit:1.4.2:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:qiskit:2.6.2:*:*:*:*:*:*:*
tags:
  - deserialization
  - rce
  - python
  - developer-tools
vendors:
  - IBM
products:
  - Qiskit SDK (1.4.2-2.6.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: IBM Qiskit SDK 1.4.2 through 2.6.2 could allow a local attacker to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-116499
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116499
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory assets using IBM Qiskit SDK versions 1.4.2 through 2.6.2
      owner: IT Operations
      due: 48h
      evidence: Vulnerability scope defined by CVE-2026-116499
  hunt_leads:
    - lead: Identify applications performing deserialization of untrusted data using Qiskit libraries
      technique_id: T1059
      data_needed:
        - Code audit logs
        - Application dependency inventory
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability stems from deserialization of untrusted data within the SDK.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Qiskit SDK to a patched version once released by IBM
      owner: IT Operations
      addresses: CVE-2026-116499
      evidence: IBM Qiskit SDK 1.4.2 through 2.6.2 is identified as vulnerable.
---

IBM Qiskit SDK versions 1.4.2 through 2.6.2 are affected by a deserialization of untrusted data vulnerability (CVE-2026-116499). A local attacker who can influence the data processed by the SDK may achieve arbitrary code execution. As of the initial disclosure, no specific exploit path or proof-of-concept code has been detailed by the vendor.

## Impact

An attacker with local access to a system running an affected version of Qiskit may be able to execute arbitrary commands, potentially leading to unauthorized data access or privilege escalation depending on the privileges of the application using the SDK.

## Recommendation

- Identify all systems and environments utilizing IBM Qiskit SDK versions 1.4.2 through 2.6.2.
- Upgrade to a non-vulnerable version of Qiskit SDK as soon as an update is released by IBM.
- Implement strict input validation for any data processed or deserialized by Qiskit components to mitigate the risk until patches are applied.
