---
title: Privilege Escalation Vulnerability in Sophos Endpoint Products for macOS
slug: 2026-08-sophos-lpe
description: A local privilege escalation vulnerability, tracked as CVE-2026-18367, affects multiple Sophos endpoint security products on macOS, potentially allowing authenticated local users to gain elevated system privileges.
date: "2026-08-14T14:05:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - macos
vendors:
  - Sophos
products:
  - Intercept X Endpoint (Central)
  - Sophos Home
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Une vulnérabilité a été découverte dans les produits Sophos. Elle permet à un attaquant de provoquer une élévation de privilèges.
    confidence_band: high
cves:
  - id: CVE-2026-18367
    cvss: 9.3
    epss: 0.00131
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1025/
  - https://sophos.com/en-us/security-advisories/sophos-sa-20260806-ep-macos-lpe
  - https://www.cve.org/CVERecord?id=CVE-2026-18367
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch vulnerable Sophos endpoints on macOS to the specified secure versions.
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory and CERT-FR alert
  mitigation_plan:
    - priority: immediate
      action: Deploy patch 2026.1.1 for Intercept X or 10.11.6 for Sophos Home.
      owner: IT Operations
      addresses: CVE-2026-18367
      evidence: Vendor advisory sophos-sa-20260806-ep-macos-lpe
---

Sophos has released a security advisory concerning a local privilege escalation vulnerability, identified as CVE-2026-18367, affecting its endpoint security software on macOS. The vulnerability impacts Intercept X Endpoint (Central) versions prior to 2026.1.1 and Sophos Home versions prior to 10.11.6. This vulnerability allows an authenticated local attacker to escalate their privileges within the context of the affected product, potentially gaining higher system-level access than their original user permissions allow. Given that endpoint security software typically operates with significant system-level privileges to perform its protective functions, successful exploitation of this flaw could facilitate further malicious activity on the compromised host. Organizations utilizing these products on macOS systems are advised to apply the vendor-provided patches immediately to mitigate the risk of local privilege escalation.

## Impact

Successful exploitation of CVE-2026-18367 results in local privilege escalation on macOS systems running vulnerable versions of Sophos Intercept X or Sophos Home. An attacker who has already obtained initial low-privilege access to a system could leverage this flaw to gain elevated permissions, effectively bypassing local security controls and potentially accessing restricted system areas, sensitive data, or performing unauthorized administrative operations.

## Recommendation

- Upgrade Sophos Intercept X Endpoint (Central) for macOS to version 2026.1.1 or later.
- Upgrade Sophos Home for macOS to version 10.11.6 or later.
- Review the official vendor advisory (sophos-sa-20260806-ep-macos-lpe) for specific implementation guidance and confirmation of patch application.
- Monitor local system logs for signs of anomalous process execution or unauthorized changes to system configuration following any identified authentication events.
