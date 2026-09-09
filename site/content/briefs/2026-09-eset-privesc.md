---
title: Privilege Escalation Vulnerability in ESET AV Remover
slug: 2026-09-eset-privesc
description: A privilege escalation vulnerability, CVE-2026-12858, in ESET AV Remover allows local attackers to gain elevated privileges on affected host systems.
date: "2026-09-09T18:50:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:eset:av_remover:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
  - security-update
vendors:
  - ESET
products:
  - AV Remover (< 1.6.17.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Une vulnérabilité a été découverte dans les produits ESET. Elle permet à un attaquant de provoquer une élévation de privilèges.
    confidence_band: high
cves:
  - id: CVE-2026-12858
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1143/
  - https://support-feed.eset.com/link/15370/17443273/ca9000
  - https://www.cve.org/CVERecord?id=CVE-2026-12858
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade ESET AV Remover to version 1.6.17.0 or later.
      owner: IT Operations
      addresses: CVE-2026-12858
      evidence: Bulletin de sécurité ESET ca9000 du 09 septembre 2026
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding a security vulnerability found in ESET AV Remover, an ESET utility used for uninstalling antivirus software. The vulnerability, tracked as CVE-2026-12858, permits an attacker with local access to the system to escalate privileges. This flaw resides in versions of AV Remover prior to 1.6.17.0. Security teams should prioritize patching this utility, as successful exploitation enables an attacker to move from a lower-privileged user context to higher-level access, potentially resulting in full system compromise. The issue was disclosed by ESET in their security bulletin ca9000 on September 9, 2026.

## Impact

Successful exploitation of CVE-2026-12858 allows an attacker to achieve privilege escalation on a compromised machine. This grants the attacker the ability to execute code with elevated rights, bypass standard security controls, and perform unauthorized modifications to the operating system or installed applications.

## Recommendation

Update all instances of ESET AV Remover to version 1.6.17.0 or later immediately to mitigate CVE-2026-12858. Consult the ESET security bulletin ca9000 for specific deployment procedures regarding the patch.
