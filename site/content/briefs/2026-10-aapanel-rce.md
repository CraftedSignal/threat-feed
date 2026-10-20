---
brief_id: brief-2026-10-20-aapanel-rce
event_id: brief-2026-10-20-aapanel-rce
revision: 1
activity_at: "2026-10-20T19:45:21Z"
title: 'aaPanel: Remote OS Command Injection via File Manager (CVE-2026-113506)'
slug: 2026-10-aapanel-rce
description: An OS command injection vulnerability exists in aaPanel versions 8.25.0 and earlier, allowing authenticated remote attackers to execute arbitrary system commands through the File Manager component.
date: "2026-10-20T19:45:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:aapanel:aapanel:*:*:*:*:*:*:*:*
tags:
  - cve-2026-113506
  - remote-code-execution
  - web-application
vendors:
  - aaPanel
products:
  - aaPanel (<= 8.25.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument sfile/dfile/access/user leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-113506
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113506
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch aaPanel to the latest version beyond 8.25.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to 8.25.0
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the aaPanel administrative login page
      owner: IT Operations
      addresses: CVE-2026-113506
      evidence: Vulnerability requires authentication
---

aaPanel, a popular web hosting control panel, contains a critical OS command injection vulnerability (CVE-2026-113506) affecting versions up to and including 8.25.0. The flaw resides within the `ExecShell` function located in `class/public/common.py` within the File Manager component. By manipulating specific input arguments - specifically `sfile`, `dfile`, `access`, or `user` - an authenticated attacker can bypass intended input sanitization and trigger the execution of arbitrary system commands on the underlying host operating system. The vulnerability is exploitable remotely, and public exploit code is available, heightening the risk of system compromise.

## Impact

Successful exploitation of this vulnerability results in full remote code execution (RCE) with the privileges of the web server process. In a hosting environment, this could allow an attacker to pivot between hosted sites, exfiltrate sensitive configuration files, modify database content, or deploy persistence mechanisms. The impact is assessed as critical due to the ease of exploitation and the potential for complete system take-over.

## Recommendation

* Update aaPanel to a version released after 8.25.0 that addresses this vulnerability.
* Implement restrictive access controls for the web administration interface to minimize the number of authenticated users capable of reaching the vulnerable File Manager component.
* Monitor server logs for suspicious system-level command execution (e.g., `whoami`, `id`, `wget`, `curl`) initiated by the web server service account.
* Apply network-level restrictions to ensure the aaPanel administrative interface is not exposed to the public internet.
