---
title: CVE-2026-77930 - Approval Bypass and Command Execution in EvoScientist
slug: 2026-10-evoscientist-bypass
description: EvoScientist versions 0.1.0 through 0.2.4 contain an approval bypass vulnerability enabling attackers to execute arbitrary shell commands via unsanitized content ingestion.
date: "2026-10-20T02:32:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:evoscientist:evoscientist:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
vendors:
  - EvoScientist
products:
  - EvoScientist (< 0.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can plant instructions in ingested content such as fetched web pages.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The agent calls start_async_task and runs commands with user privileges and environment secrets.
    confidence_band: high
cves:
  - id: CVE-2026-77930
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77930
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade EvoScientist to version 0.2.5
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-77930 patch availability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 0.2.5
      owner: IT Operations
      addresses: CVE-2026-77930
      evidence: NVD source.
---

EvoScientist versions 0.1.0 through 0.2.4 are susceptible to an approval bypass vulnerability (CVE-2026-77930) that allows unauthenticated or remote attackers to achieve command execution. The flaw exists because the software fails to implement an interrupt_on gate when delegating tasks to asynchronous sub-agents. By planting malicious instructions within ingested content - such as external web pages - an attacker can trick the EvoScientist agent into invoking the start_async_task function. This results in the execution of arbitrary shell commands with the privileges and environment secrets of the user running the agent. This vulnerability is significant because it grants an attacker direct access to sensitive credentials and the ability to interact with the underlying host filesystem and network.

## Impact

Successful exploitation allows for full command execution on the host machine. In enterprise environments where the EvoScientist agent is configured with high-privilege service accounts or has access to sensitive API keys and environment variables, this vulnerability could lead to total system compromise, data exfiltration, or lateral movement within the network.

## Recommendation

* Upgrade EvoScientist to version 0.2.5 or later immediately to patch the missing interrupt_on gate logic.
* Restrict the privileges of the service account running the EvoScientist agent to the minimum necessary for its intended tasks.
* Implement egress filtering to prevent the agent from fetching arbitrary or untrusted external web content.
