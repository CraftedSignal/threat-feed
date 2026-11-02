---
brief_id: brief-2026-11-02-lobechat-path-traversal
event_id: brief-2026-11-02-lobechat-path-traversal
revision: 1
activity_at: "2026-11-02T07:16:58Z"
title: 'LobeChat: Path traversal arbitrary file write (CVE-2026-120315)'
slug: 2026-11-lobechat-path-traversal
description: LobeChat versions 1.84.26 through 2.1.48 contain a path traversal vulnerability in writeTempFile that allows authenticated users to achieve remote code execution by overwriting application startup scripts.
date: "2026-11-02T07:16:58Z"
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
  validation_status: Source confirmed; remediation version verified.
cpes:
  - cpe:2.3:a:lobehub:lobechat:*:*:*:*:*:*:*:*
vendors:
  - LobeHub
products:
  - LobeChat (1.84.26 <= v < 2.1.49)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LobeHub Chat from 1.84.26 before 2.1.49 contains a path traversal vulnerability that allows authenticated users to write arbitrary files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can create a file record via file.createFile with a traversal name, then trigger document parsing to overwrite application files like startServer.js for code execution.
    confidence_band: high
cves:
  - id: CVE-2026-120315
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120315
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LobeChat to 2.1.49 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-120315 vulnerability requires patch.
  hunt_leads:
    - lead: Hunt for file.createFile requests containing path traversal sequences (e.g., ../, ..\) in access logs or application audit logs.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Authenticated users can exploit this flaw by providing malicious file names to the file.createFile method.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.1.49 or later
      owner: IT Operations
      addresses: CVE-2026-120315
      evidence: NVD vulnerability disclosure
---

LobeChat versions 1.84.26 up to 2.1.49 contain a path traversal vulnerability in the `writeTempFile()` function. An authenticated attacker can supply a malicious filename to the `file.createFile` method to write files outside of the intended directory. By triggering document parsing features, the attacker can overwrite sensitive application files, such as `startServer.js`, to achieve remote code execution or cause denial of service. 

## Impact

Authenticated users can achieve remote code execution (RCE) by overwriting application startup files or render the application unusable through arbitrary file overwriting (Denial of Service).

## Recommendation

Update LobeChat instances to version 2.1.49 or later immediately to patch the path traversal vulnerability in the `writeTempFile` function. Perform an audit of temporary file directories and application source code integrity to ensure no malicious files have been planted or existing files modified by unauthorized users prior to patching.
