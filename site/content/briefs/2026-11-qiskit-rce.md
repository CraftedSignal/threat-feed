---
brief_id: brief-2026-11-08-qiskit-rce
event_id: brief-2026-11-08-qiskit-rce
revision: 1
activity_at: "2026-11-08T19:35:07Z"
title: 'IBM Qiskit SDK: Arbitrary code execution via corrupted unitary matrix (CVE-2026-116501)'
slug: 2026-11-qiskit-rce
description: IBM Qiskit SDK versions 2.4.0 through 2.6.1 are vulnerable to arbitrary code execution due to an out-of-bounds write flaw caused by improper input validation when processing corrupted unitary matrices.
date: "2026-11-08T19:35:07Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:qiskit:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Qiskit SDK (2.4.0-2.6.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: IBM Qiskit SDK 2.4.0 through 2.6.1 could allow a local attacker to execute arbitrary code due to an out-of-bounds write caused by improper input validation when accessing a corrupted unitary matrix.
    confidence_band: high
cves:
  - id: CVE-2026-116501
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116501
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and patch instances of IBM Qiskit SDK versions 2.4.0-2.6.1
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions range 2.4.0-2.6.1 identified in source.
  hunt_leads:
    - lead: Identify applications loading Qiskit SDK libraries and monitor for abnormal child process spawning or unexpected memory write patterns in processes linked to matrix processing tasks.
      technique_id: T1059
      data_needed:
        - Application dependency inventory logs
        - Endpoint process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary code execution via corrupted input processing.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest IBM Qiskit SDK version
      owner: IT Operations
      addresses: CVE-2026-116501
      evidence: Upgrading software to a version beyond 2.6.1 addresses the vulnerability.
---

IBM Qiskit SDK versions 2.4.0 through 2.6.1 contain an out-of-bounds write vulnerability (CVE-2026-116501) that can result in arbitrary code execution. The vulnerability is triggered during the processing of a corrupted unitary matrix, which occurs due to improper input validation within the SDK. This flaw allows a local attacker to potentially execute arbitrary code within the application's runtime context.

## Impact

Successful exploitation could allow a local attacker to execute arbitrary code within the memory space of the process utilizing the vulnerable Qiskit SDK, potentially leading to unauthorized data access or full control over the process execution environment.

## Recommendation

* Inventory systems and applications currently utilizing IBM Qiskit SDK to identify versions within the 2.4.0 to 2.6.1 range.
* Update all instances of IBM Qiskit SDK to the latest available patched version provided by IBM.
* Restrict access to files or data sources that provide input (specifically unitary matrices) to Qiskit-based applications to prevent the processing of malicious or corrupted data.
