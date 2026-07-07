---
title: Multiples vulnérabilités dans OpenSSH
slug: 2026-07-openssh-multi-vulns
description: Multiple vulnerabilities in OpenSSH versions prior to 10.4 allow attackers to bypass security policies, cause denial of service, and exploit other unspecified security issues, requiring users to update to OpenSSH 10.4 or later.
date: "2026-07-06T13:53:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - openssh
  - network
vendors:
  - OpenSSH
products:
  - OpenSSH (< 10.4)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: contournement de la politique de sécurité
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: déni de service
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0836/
  - https://www.openssh.com/txt/release-10.4
---

CERT-FR has disclosed multiple unpatched vulnerabilities impacting OpenSSH versions prior to 10.4, with the advisory published on July 6, 2026. These vulnerabilities pose significant risks, including the potential for security policy bypass, denial of service (DoS) attacks, and other unspecified security concerns. Attackers could leverage these flaws to gain unauthorized access, disrupt critical services, or compromise the integrity of affected systems. While the specific methods of exploitation are not detailed, the broad nature of the impacts underscores the urgency for immediate remediation. Given OpenSSH's widespread use as a foundational secure communication protocol, any unpatched vulnerability presents a critical attack surface for adversaries across various sectors. Organizations must prioritize patching to mitigate potential exposure.

## Attack Chain

This advisory describes multiple vulnerabilities without providing specific, documented attack chain steps or observed exploitation scenarios. Therefore, a detailed attack chain cannot be constructed based on the provided information.

## Impact

The identified vulnerabilities in OpenSSH versions earlier than 10.4 could lead to severe consequences for affected organizations. Successful exploitation may result in a complete bypass of security policies, allowing attackers to perform unauthorized actions or access sensitive data. Furthermore, the denial of service vulnerability could render critical SSH services unavailable, severely impacting operational continuity and business processes. While specific victim counts or targeted sectors are not detailed in this advisory, the pervasive deployment of OpenSSH across enterprise and critical infrastructure environments means the potential impact is broad and could affect any organization relying on the software for secure remote access and file transfer.

## Recommendation

*   Immediately update all OpenSSH installations to version 10.4 or later, as referenced in the OpenSSH security bulletin `https://www.openssh.com/txt/release-10.4`.
*   Refer to the "Documentation" section of the CERT-FR advisory at `https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0836/` and the OpenSSH security bulletin for detailed patching instructions specific to your distribution.
