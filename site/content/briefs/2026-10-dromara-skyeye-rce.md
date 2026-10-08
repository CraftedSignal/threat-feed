---
title: Unauthenticated Remote Code Execution in Dromara Skyeye
slug: 2026-10-dromara-skyeye-rce
description: Dromara Skyeye contains a missing authentication vulnerability in its bundled xxl-job-admin JobInfoController, allowing unauthenticated attackers to execute arbitrary shell, Python, or PowerShell jobs on the executor host.
date: "2026-10-08T22:02:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dromara:skyeye:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application-security
vendors:
  - Dromara
products:
  - Skyeye (<= 003549ae5615bd114ba5bb8ddf6a8e8ead97c321)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can POST GLUE_SHELL, GLUE_PYTHON, or GLUE_POWERSHELL jobs with attacker-supplied glueSource to /jobinfo/addAndStart
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: attackers can POST... GLUE_POWERSHELL jobs
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: attackers can POST... GLUE_PYTHON jobs
    confidence_band: high
cves:
  - id: CVE-2026-107779
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107779
rules:
  - title: Detect CVE-2026-107779 Exploitation - Unauthorized Job Submission
    description: Detects unauthenticated POST requests to the /jobinfo/addAndStart endpoint associated with Skyeye job execution exploitation.
    platform: sigma
    severity: critical
    tactics:
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy web server rule to monitor /jobinfo/addAndStart
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-107779 vulnerability description
  mitigation_plan:
    - priority: immediate
      action: Isolate Skyeye management interfaces from external access
      owner: IT Operations
      addresses: CVE-2026-107779
      evidence: NVD vulnerability severity CVSS 9.8
---

Dromara Skyeye, up to and including commit 003549ae5615bd114ba5bb8ddf6a8e8ead97c321, is vulnerable to a critical missing authentication vulnerability (CVE-2026-107779). The vulnerability exists within the bundled xxl-job-admin JobInfoController endpoints, specifically those annotated with @PermissionLimit(limit = false). This flaw allows unauthenticated remote attackers to interact with the /jobinfo/addAndStart endpoint. By submitting crafted job payloads, an attacker can specify GLUE_SHELL, GLUE_PYTHON, or GLUE_POWERSHELL job types with arbitrary glueSource code. This effectively grants the attacker the ability to execute unauthorized commands, stop jobs, or delete jobs directly on the underlying executor host. Given the severity of the remote code execution (RCE) vector and the ease of exploitation, this vulnerability poses a significant threat to any infrastructure deploying the affected version of Skyeye.

## Impact

Successful exploitation results in full remote code execution on the executor host. Attackers can leverage this access to perform lateral movement, data exfiltration, or complete system compromise. Any environment utilizing the affected Dromara Skyeye build is at high risk of unauthorized command execution.

## Recommendation

* Immediately restrict network access to the Dromara Skyeye management interface, ensuring it is not exposed to the public internet.
* Audit web server logs for HTTP POST requests targeting /jobinfo/addAndStart from unauthorized source IP addresses.
* Monitor for suspicious child processes spawned by the Java process hosting the xxl-job-admin component, specifically looking for shell execution (cmd.exe, /bin/sh, /bin/bash) or script interpreter invocations (python, powershell.exe).
* Update Dromara Skyeye to a version beyond commit 003549ae5615bd114ba5bb8ddf6a8e8ead97c321 as soon as a patch is released by the maintainers.
