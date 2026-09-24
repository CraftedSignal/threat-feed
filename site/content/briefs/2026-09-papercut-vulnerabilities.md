---
title: Multiple Vulnerabilities in PaperCut Software
slug: 2026-09-papercut-vulnerabilities
description: PaperCut has released security updates addressing critical vulnerabilities including remote code execution, unauthorized data access, and XSS across PaperCut Hive and PaperCut NG/MF platforms.
date: "2026-09-24T13:57:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - patch-management
vendors:
  - PaperCut
products:
  - PaperCut Hive Embedded Application (< 2.3.0)
  - PaperCut NG/MF 25.x (< 25.0.13)
  - PaperCut NG/MF 26.x (< 26.0.5)
cves:
  - id: CVE-2026-11744
  - id: CVE-2026-14780
  - id: CVE-2026-82077
  - id: CVE-2026-87739
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1223/
  - https://www.papercut.com/kb/Main/security-bulletin-sep-2026/
  - https://www.cve.org/CVERecord?id=CVE-2026-11744
  - https://www.cve.org/CVERecord?id=CVE-2026-14780
  - https://www.cve.org/CVERecord?id=CVE-2026-82077
  - https://www.cve.org/CVERecord?id=CVE-2026-87739
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade all instances of PaperCut Hive, NG, and MF to the corrected versions identified in the September 2026 bulletin.
      owner: IT Operations
      addresses: CVE-2026-11744, CVE-2026-14780, CVE-2026-82077, CVE-2026-87739
      evidence: PaperCut security-bulletin-sep-2026
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding multiple vulnerabilities identified in various PaperCut software products. These security flaws impact PaperCut Hive Embedded Application, PaperCut NG/MF 25.x, and PaperCut NG/MF 26.x. The identified vulnerabilities pose significant risks, including potential remote code execution (RCE), unauthorized data disclosure, and remote cross-site scripting (XSS) attacks. Attackers who exploit these vulnerabilities could potentially bypass established security policies or gain unauthorized access to sensitive data processed by print management systems. Organizations utilizing affected versions are advised to update their deployments immediately to the versions specified by the vendor as secured.

## Impact

Successful exploitation of these vulnerabilities could result in a complete compromise of the print management server or application, leading to data confidentiality breaches, unauthorized execution of arbitrary code, and the potential for cross-site scripting attacks against administrative interfaces. These systems are typically deployed across corporate and institutional networks, making them high-value targets for internal reconnaissance and lateral movement.

## Recommendation

Prioritize the patching of all affected PaperCut instances to the secure versions listed in the vendor security bulletin.
- Upgrade PaperCut Hive Embedded Application to version 2.3.0 or later.
- Upgrade PaperCut NG/MF 25.x to version 25.0.13 or later.
- Upgrade PaperCut NG/MF 26.x to version 26.0.5 or later.
- Review the official PaperCut security bulletin (linked in references) for full technical details regarding CVE-2026-11744, CVE-2026-14780, CVE-2026-82077, and CVE-2026-87739.
