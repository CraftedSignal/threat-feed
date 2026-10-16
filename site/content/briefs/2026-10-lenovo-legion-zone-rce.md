---
title: Remote Code Execution in Lenovo Legion Zone Application
slug: 2026-10-lenovo-legion-zone-rce
description: A vulnerability in the Lenovo Legion Zone application allows an attacker on the same logical network to execute arbitrary code on the host system.
date: "2026-10-16T00:41:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lenovo:legion_zone:*:*:*:*:*:*:*:*
vendors:
  - Lenovo
products:
  - Legion Zone
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to execute arbitrary code on the host system.
    confidence_band: high
cves:
  - id: CVE-2026-75941
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75941
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory enterprise assets for Lenovo Legion Zone installation
      owner: IT Operations
      due: 48h
      evidence: Source confirms application vulnerability (CVE-2026-75941)
  mitigation_plan:
    - priority: immediate
      action: Remove or uninstall Lenovo Legion Zone application
      owner: IT Operations
      addresses: CVE-2026-75941
      evidence: NVD vulnerability disclosure
---

CVE-2026-75941 describes a critical vulnerability within the Lenovo Legion Zone application, a software utility distributed primarily in the Chinese market. The vulnerability allows an unauthenticated attacker present on the same logical network to achieve remote code execution on the target Windows system. Given the application's access requirements and the nature of the flaw, successful exploitation could grant an attacker complete control over the affected host. Defenders operating in regions where this software may be installed should prioritize identifying installations and evaluating the necessity of the application due to the potential for full system compromise.

## Impact

Successful exploitation of CVE-2026-75941 results in full system compromise for the affected host. While primarily distributed in the Chinese market, any enterprise environment where this software is present faces high risk from lateral movement or local network-based attacks.

## Recommendation

- Perform an inventory search for the 'Lenovo Legion Zone' application across the workstation fleet using endpoint management tools.
- Monitor local network traffic for anomalous behavior originating from or targeting Windows workstations running Lenovo software.
- Remove or disable the Lenovo Legion Zone application if it is not strictly required for business operations.
