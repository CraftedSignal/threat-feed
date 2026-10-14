---
title: CISA Adds Four Actively Exploited Vulnerabilities to KEV Catalog
slug: 2026-10-cisa-kev-update
description: CISA added four vulnerabilities to the Known Exploited Vulnerabilities (KEV) Catalog, including code injection, path traversal, and authentication flaws affecting Palo Alto Networks, Cisco, and Ahsay products.
date: "2026-10-14T20:49:20Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability-management
  - cisa-kev
  - patch-management
vendors:
  - Palo Alto Networks
  - Cisco
  - Ahsay
products:
  - PAN-OS
  - Secure Email Gateway
  - AhsayCBS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog, based on evidence of active exploitation.
    confidence_band: high
cves:
  - id: CVE-2026-0322
  - id: CVE-2026-76519
    cvss: 9.8
  - id: CVE-2026-105133
    cvss: 7.3
    epss: 0.00383
  - id: CVE-2026-105134
    cvss: 10
    epss: 0.01843
references:
  - https://www.cisa.gov/news-events/alerts/2026/10/14/cisa-adds-four-known-exploited-vulnerabilities-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-0322
  - https://www.cve.org/CVERecord?id=CVE-2026-76519
  - https://www.cve.org/CVERecord?id=CVE-2026-105133
  - https://www.cve.org/CVERecord?id=CVE-2026-105134
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, and CVE-2026-105134 on all affected assets.
      owner: IT Operations
      due: 24h
      evidence: CISA BOD 26-04 requirement for prioritized rapid remediation of KEV catalog items.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security updates for PAN-OS, Secure Email Gateway, and AhsayCBS.
      owner: IT Operations
      addresses: CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, CVE-2026-105134
      evidence: CISA KEV Catalog remediation guidance.
---

On October 14, 2026, CISA updated its Known Exploited Vulnerabilities (KEV) Catalog to include four vulnerabilities that have been identified as being actively exploited in the wild. The newly added vulnerabilities affect widely used enterprise and network security infrastructure, specifically Palo Alto Networks PAN-OS (CVE-2026-0322), Cisco Secure Email Gateway (CVE-2026-76519), and Ahsay AhsayCBS (CVE-2026-105133, CVE-2026-105134). 

These vulnerabilities represent a diverse set of attack vectors, ranging from improper authentication and path traversal to remote code execution via command and code injection. Given their presence in the KEV catalog and evidence of active exploitation, these flaws pose a significant risk to organizational environments. In accordance with Binding Operational Directive (BOD) 26-04, federal agencies are required to prioritize the remediation of these vulnerabilities on internet-facing assets. All organizations are encouraged to review their inventory against these CVEs and prioritize patching to prevent unauthorized access or system takeover.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access, total control of the affected asset, or remote command execution. Targeted sectors include organizations relying on Cisco email infrastructure, Palo Alto network perimeters, and Ahsay backup solutions. The volume of victims remains internal to organizational risk management reports, but the inclusion in the CISA KEV catalog confirms these are being used as viable initial access or lateral movement vectors by malicious actors.

## Recommendation

* Prioritize remediation for CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, and CVE-2026-105134 across all internet-facing and internal assets immediately.
* Review network egress and ingress logs for signs of anomalous traffic or unauthorized command execution related to these products.
* Implement risk-based vulnerability management practices as outlined in BOD 26-04, focusing on assets that grant total control post-exploitation.
* Conduct a compromise assessment to determine if these assets were accessed by unauthorized actors prior to the application of security patches.
