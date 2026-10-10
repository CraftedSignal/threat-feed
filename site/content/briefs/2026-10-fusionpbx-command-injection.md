---
title: FusionPBX OS Command Injection via Malicious Caller-ID
slug: 2026-10-fusionpbx-command-injection
description: FusionPBX versions up to 5.6.5 contain an unauthenticated OS command injection vulnerability in the call_recordings::download function, allowing arbitrary code execution via crafted Caller-ID fields.
date: "2026-10-10T15:55:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fusionpbx:fusionpbx:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - web-application
vendors:
  - FusionPBX
products:
  - FusionPBX (<= 5.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: FusionPBX through 5.6.5 contains an OS command injection vulnerability in call_recordings::download() that allows unauthenticated attackers to execute commands
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: attackers can embed shell metacharacters like $(...) in the Caller-ID name or number, executing commands as the web server user
    confidence_band: high
cves:
  - id: CVE-2026-108161
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108161
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade FusionPBX to a version higher than 5.6.5
      owner: IT Operations
      due: 48h
      evidence: Source advisory identifies 5.6.5 as the affected limit
  mitigation_plan:
    - priority: immediate
      action: Upgrade FusionPBX to latest available release
      owner: IT Operations
      addresses: CVE-2026-108161
      evidence: NVD advisory for CVE-2026-108161
---

FusionPBX versions through 5.6.5 are susceptible to an OS command injection vulnerability located within the `call_recordings::download()` function. This vulnerability allows an unauthenticated remote attacker to execute arbitrary system commands by crafting malicious input in the Caller-ID name or number field when placing a call. When the `record_name` filename template configuration is enabled, the application improperly handles these fields during the process of bundling multiple call recordings into a ZIP file for a privileged user. Because the underlying system processes these filenames, the injected shell metacharacters, such as `$(...)`, are evaluated by the shell under the context of the web server user. This vulnerability presents a high risk as it permits code execution without requiring administrative authentication on the FusionPBX interface.

## Impact

Successful exploitation allows unauthenticated attackers to achieve remote command execution with the privileges of the web server user. This could lead to full application compromise, lateral movement within the network, or potential data exfiltration of call recordings. Given FusionPBX's role as a PBX system, this compromise could also facilitate unauthorized interception of voice traffic or manipulation of call routing configurations.

## Recommendation

* Upgrade FusionPBX to a version later than 5.6.5 to remediate the vulnerability in `call_recordings::download()`.
* Monitor web server logs for suspicious requests involving the `call_recordings` module that include shell metacharacters like `$(`, `` ` ``, or `|` in request parameters.
* Restrict access to the FusionPBX administrative interface to trusted management networks only, mitigating the ability for external attackers to trigger the ZIP download function.
