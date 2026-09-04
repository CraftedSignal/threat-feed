---
title: Critical Remote Code Execution Vulnerabilities in VMware Fusion and Workstation
slug: 2026-09-vmware-vulnerabilities
description: VMware has released security updates for Fusion and Workstation to address multiple vulnerabilities, including CVE-2026-59346 and CVE-2026-59347, which could allow a remote attacker to execute arbitrary code.
date: "2026-09-04T18:06:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - virtualization
  - rce
vendors:
  - VMware
products:
  - Fusion (< 26H1u1)
  - Workstation (< 26H1u1)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1114/
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288
  - https://www.cve.org/CVERecord?id=CVE-2026-59346
  - https://www.cve.org/CVERecord?id=CVE-2026-59347
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade VMware Fusion and VMware Workstation to version 26H1u1 or later
      owner: IT Operations
      addresses: CVE-2026-59346, CVE-2026-59347
      evidence: Broadcom security advisory 38288
---

On September 3, 2026, VMware (Broadcom) published security advisory 38288 detailing multiple vulnerabilities affecting VMware Fusion and VMware Workstation. These flaws include CVE-2026-59346 and CVE-2026-59347, which pose a significant risk as they may allow a remote, unauthenticated attacker to achieve arbitrary code execution on the host operating system running the virtualization software. Given the potential for full system compromise, organizations utilizing these virtualization products must prioritize the deployment of updates to version 26H1u1 or later. The vulnerabilities impact Fusion and Workstation deployments across supported operating systems, including Windows and macOS environments. Defenders should ensure patching is completed immediately to mitigate the risk of exploitation.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code with the privileges of the virtualization application, potentially leading to total system compromise of the host machine. This affects any environment where Fusion or Workstation is installed, including enterprise developer workstations and lab environments.

## Recommendation

* Patch all instances of VMware Fusion and VMware Workstation to version 26H1u1 or later immediately.
* Refer to Broadcom security advisory 38288 for specific installation instructions and patch availability.
* Monitor for unauthorized process execution originating from the virtualization host process (vmware-vmx.exe or equivalent).
