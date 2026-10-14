---
title: OS Command Injection in buildebooks
slug: 2026-10-buildebooks-command-injection
description: The buildebooks package before 0.2.2 contains an OS command injection vulnerability in lib/kindle.js that allows attackers to execute arbitrary system commands via crafted EPUB filenames.
date: "2026-10-14T16:37:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:buildebooks_project:buildebooks:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - supply-chain
  - nodejs
products:
  - buildebooks (< 0.2.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: buildebooks before 0.2.2 contains an OS command injection vulnerability in lib/kindle.js that allows attackers to execute commands by supplying a crafted EPUB file name passed to kindlegen via child_process.exec.
    confidence_band: high
cves:
  - id: CVE-2026-110637
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110637
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade buildebooks to 0.2.2 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability notice indicates fix in 0.2.2
  mitigation_plan:
    - priority: immediate
      action: Upgrade buildebooks to 0.2.2
      owner: IT Operations
      addresses: CVE-2026-110637
      evidence: NVD advisory
---

The buildebooks package, prior to version 0.2.2, is susceptible to an OS command injection vulnerability located within the 'lib/kindle.js' file. This flaw originates from improper input sanitization when processing book project data. Specifically, when the 'kindle' configuration is set to true, the application passes user-supplied EPUB filenames or project folder names directly to the 'child_process.exec' function. 

An attacker can exploit this by creating a book project with a maliciously crafted filename containing shell metacharacters. When the library processes these names, it executes the injected commands within the context of the user running the build process. This vulnerability is significant as it provides a mechanism for remote code execution on systems where buildebooks is utilized to automate ebook generation. Defenders should prioritize updating to version 0.2.2 or later to eliminate the underlying command injection vector.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands with the privileges of the user running the build process. This can lead to full system compromise, exfiltration of environment variables (such as CI/CD secrets), or the modification of the build pipeline to introduce persistent threats into downstream artifacts. The vulnerability affects all users running vulnerable versions of buildebooks in build environments, CI/CD pipelines, or desktop workstations.

## Recommendation

* Upgrade the buildebooks package to version 0.2.2 or later immediately.
* Audit build logs and CI/CD pipelines for unusual process execution patterns initiated by the node runtime.
* Apply the principle of least privilege by running build processes in isolated containers with minimal system permissions.
