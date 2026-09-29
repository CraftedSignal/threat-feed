---
title: Ghostscript Local Privilege Escalation Vulnerability
slug: 2026-09-ghostscript-privilege-escalation
description: A vulnerability in the Ghostscript interpreter allows a local attacker to escalate privileges by processing specifically crafted documents.
date: "2026-09-29T16:18:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - ghostscript
  - vulnerability
vendors:
  - Artifex Software
products:
  - Ghostscript
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local attacker can exploit a vulnerability in Ghostscript to increase their privileges.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3628
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all servers and workstations running Ghostscript for version management.
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Identify applications spawning Ghostscript processes (gs, gswin64c) that receive external input.
      technique_id: T1068
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Ghostscript is the entry point for the described privilege escalation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ghostscript to the latest vendor-supplied version.
      owner: IT Operations
      addresses: Ghostscript local privilege escalation
  gaps:
    - Lack of specific exploit indicators.
---

A security vulnerability exists in the Ghostscript interpreter that permits a local attacker to perform privilege escalation. The issue stems from insufficient security constraints within the interpreter, which can be bypassed when the software processes malicious documents or input files. This vulnerability poses a significant risk to systems that use Ghostscript to perform automated document conversion or processing, such as web servers or document management systems that handle untrusted user-submitted files. Attackers can leverage this flaw to gain elevated permissions on the host system, potentially leading to unauthorized access, code execution, or data manipulation. Defensive teams should prioritize auditing systems where Ghostscript is invoked by applications processing external user input.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escalate their privileges to those of the user running the Ghostscript process. In enterprise environments, this often results in full system compromise if the service is running with high privileges. Impacted sectors include any organization relying on Ghostscript for document processing, particularly in Linux, Windows, or macOS environments where the interpreter is integrated into administrative or web-facing workflows.

## Recommendation

Prioritize patching Ghostscript across all affected environments as updates become available from Artifex Software or the relevant OS package maintainer. Given the local nature of the vulnerability, monitor system logs for unusual process execution chains involving 'gs' or 'gswin64c' spawned by web server or document service accounts.
