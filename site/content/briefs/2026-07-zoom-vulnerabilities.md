---
title: Multiple Vulnerabilities in Zoom Video Communications Rooms and Workplace
slug: 2026-07-zoom-vulnerabilities
description: Multiple vulnerabilities have been identified in Zoom Video Communications Rooms and Zoom Video Communications Workplace, which an attacker can exploit to elevate privileges and ultimately take control of a user account.
date: "2026-07-15T10:42:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - privilege-escalation
  - account-takeover
  - collaboration
vendors:
  - Zoom Video Communications
products:
  - Zoom Video Communications Rooms
  - Zoom Video Communications Workplace
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein Angreifer kann mehrere Schwachstellen in Zoom Video Communications Rooms und Zoom Video Communications Workplace ausnutzen, um seine Privilegien zu erhöhen
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: und die Kontrolle über ein Konto zu übernehmen.
    confidence_band: med
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2353
---

The German Federal Office for Information Security (BSI), through its CERT-Bund advisory service, has warned of multiple critical vulnerabilities discovered in Zoom Video Communications Rooms and Zoom Video Communications Workplace products. These flaws, if exploited, could allow an unauthenticated or authenticated attacker to escalate their privileges within the system and ultimately gain full control over user accounts. While the advisory from BSI (WID-SEC-2026-2353) does not detail specific CVEs, attacker groups, or in-the-wild exploitation, it emphasizes the potential for significant impact, including unauthorized access and manipulation of communication sessions and sensitive data. Organizations utilizing Zoom Rooms or Zoom Workplace are urged to address these vulnerabilities promptly to prevent potential compromise of their collaboration infrastructure.

## Attack Chain

1. An attacker identifies a vulnerable Zoom Video Communications Rooms or Zoom Video Communications Workplace instance.
2. The attacker targets the vulnerable service, potentially by sending specially crafted network requests or manipulating client-side interactions.
3. Exploitation of the initial vulnerability leads to privilege escalation, allowing the attacker to execute code or access resources with elevated permissions on the affected system.
4. Leveraging the newly acquired elevated privileges, the attacker exploits additional vulnerabilities or misconfigurations.
5. These subsequent actions enable the attacker to gain unauthorized control over a legitimate user account within the Zoom environment.
6. The attacker can then use the compromised account to access confidential meetings, manipulate settings, or exfiltrate sensitive data associated with the account.

## Impact

Successful exploitation of these vulnerabilities could lead to significant security breaches for organizations using affected Zoom products. Attackers gaining control over user accounts can access sensitive communication, impersonate legitimate users, and potentially compromise critical business operations. The lack of specific details regarding the vulnerabilities makes it difficult to assess the full scope of potential damage, but privilege escalation and account takeover pose a substantial risk to data confidentiality, integrity, and availability within the Zoom ecosystem. Without patching, organizations remain exposed to unauthorized access and potential data loss.

## Recommendation

* Consult the official Zoom security advisories and promptly apply all available security patches and updates for Zoom Video Communications Rooms and Zoom Video Communications Workplace as recommended by the vendor.
* Regularly review user permissions and implement the principle of least privilege for all Zoom accounts to minimize the impact of potential account compromise, referencing the `Zoom Video Communications Rooms` and `Zoom Video Communications Workplace` products.
* Monitor your Zoom environment for unusual activity, such as unauthorized login attempts or unexpected changes to account settings, using available platform logs from `Zoom`.
