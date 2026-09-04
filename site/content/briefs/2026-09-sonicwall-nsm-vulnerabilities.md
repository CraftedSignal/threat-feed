---
title: Multiple Vulnerabilities in SonicWall Network Security Manager
slug: 2026-09-sonicwall-nsm-vulnerabilities
description: SonicWall Network Security Manager (NSM) versions prior to 4.3.1-R4 contain multiple vulnerabilities, including CVE-2026-78327, CVE-2026-78328, and CVE-2026-81939, that allow for remote code execution, privilege escalation, and security policy bypass.
date: "2026-09-04T18:06:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - privilege-escalation
  - patch-management
vendors:
  - SonicWall
products:
  - Network Security Manager On-Prem (< 4.3.1-R4)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1115/
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0015
  - https://www.cve.org/CVERecord?id=CVE-2026-78327
  - https://www.cve.org/CVERecord?id=CVE-2026-78328
  - https://www.cve.org/CVERecord?id=CVE-2026-81939
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade SonicWall Network Security Manager On-Prem to version 4.3.1-R4 or later.
      owner: IT Operations
      addresses: CVE-2026-78327, CVE-2026-78328, CVE-2026-81939
      evidence: Vendor security bulletin SNWLID-2026-0015
---

On September 4, 2026, the French National Cybersecurity Agency (ANSSI) and SonicWall released advisories detailing multiple high-severity vulnerabilities affecting SonicWall Network Security Manager (NSM) On-Prem appliances. The affected products include virtual machine deployments across VMWare, Hyper-V, Azure, and KVM platforms running versions earlier than 4.3.1-R4. These vulnerabilities, specifically identified as CVE-2026-78327, CVE-2026-78328, and CVE-2026-81939, collectively expose organizations to risks of remote code execution, privilege escalation, and bypass of established security policies. Given the critical nature of these flaws and the potential for unauthenticated or elevated access within a central management platform, immediate patching is required. Organizations running affected versions should prioritize updates to release 4.3.1-R4 or later as outlined in vendor bulletin SNWLID-2026-0015.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized actors to execute arbitrary code with elevated privileges, potentially leading to full system compromise of the Network Security Manager appliance. As NSM is used for the centralized management of firewall environments, a breach of this platform could allow an attacker to gain broad control over network security policies, disable security controls, or facilitate lateral movement into protected internal network segments.

## Recommendation

Prioritize the immediate upgrade of all SonicWall Network Security Manager On-Prem appliances to version 4.3.1-R4 or later to remediate CVE-2026-78327, CVE-2026-78328, and CVE-2026-81939. Monitor system logs for unexpected administrative account activity or unauthorized configuration changes following the application of the vendor patches.
