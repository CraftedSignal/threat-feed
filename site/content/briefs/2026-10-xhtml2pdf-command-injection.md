---
title: OS Command Injection in xhtml2pdf
slug: 2026-10-xhtml2pdf-command-injection
description: The xhtml2pdf library before version 0.2.19 contains an OS command injection vulnerability in the pisa.startViewer() function allowing arbitrary command execution via crafted filenames.
date: "2026-10-14T16:37:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xhtml2pdf:xhtml2pdf:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - vulnerability
  - rce
products:
  - xhtml2pdf (< 0.2.19)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: An attacker can exploit this by supplying a crafted file name containing shell metacharacters and double quotes when utilizing the -s/--start-viewer CLI flag, leading to arbitrary command execution via os.system.
    confidence_band: high
cves:
  - id: CVE-2026-110642
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110642
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade xhtml2pdf to version 0.2.19 or later
      owner: IT Operations
      addresses: CVE-2026-110642
      evidence: Source documentation for CVE-2026-110642
---

The xhtml2pdf Python library contains an OS command injection vulnerability in the pisa.startViewer() function, tracked as CVE-2026-110642. The vulnerability arises from improper sanitization of file names when using the -s or --start-viewer command-line arguments. Specifically, the pisa.startViewer() function utilizes the os.system() call to process file paths, which allows for the interpolation of shell metacharacters and double quotes. An attacker who can influence the filename provided to the tool can escape the intended context and execute arbitrary OS commands with the privileges of the user running the xhtml2pdf utility. This flaw affects all versions of xhtml2pdf prior to 0.2.19. Defenders should identify applications or automation pipelines that utilize this library and upgrade to version 0.2.19 or later immediately.
