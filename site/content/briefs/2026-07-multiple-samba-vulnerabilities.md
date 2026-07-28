---
title: Multiple Vulnerabilities in Samba
slug: 2026-07-multiple-samba-vulnerabilities
description: Multiple vulnerabilities have been discovered in Samba, a network file sharing service, which could allow a remote attacker to trigger a denial of service, compromise data confidentiality, and bypass security policies.
date: "2026-07-28T14:21:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - samba
  - denial-of-service
  - data-breach
  - security-bypass
vendors:
  - Samba
products:
  - Samba (< 4.22.10)
  - Samba (4.23.x < 4.23.9)
  - Samba (4.24.x < 4.24.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Déni de service à distance
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Network Shared Drive
    evidence: Atteinte à la confidentialité des données
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Contournement de la politique de sécurité
    confidence_band: high
cves:
  - id: CVE-2025-58218
    cvss: 7.2
    epss: 0.00354
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0939/
  - https://www.samba.org/samba/security/CVE-2026-58216.html
  - https://www.samba.org/samba/security/CVE-2026-58218.html
  - https://www.samba.org/samba/security/CVE-2026-58221.html
  - https://www.samba.org/samba/security/CVE-2026-58222.html
  - https://www.samba.org/samba/security/CVE-2026-58224.html
  - https://www.samba.org/samba/security/CVE-2026-6949.html
  - https://www.cve.org/CVERecord?id=CVE-2025-58218
  - https://www.cve.org/CVERecord?id=CVE-2026-58216
  - https://www.cve.org/CVERecord?id=CVE-2026-58218
  - https://www.cve.org/CVERecord?id=CVE-2026-58221
  - https://www.cve.org/CVERecord?id=CVE-2026-58222
  - https://www.cve.org/CVERecord?id=CVE-2026-58224
  - https://www.cve.org/CVERecord?id=CVE-2026-6949
---

On July 28, 2026, the French National Agency for the Security of Information Systems (ANSSI) CERT-FR issued an advisory detailing multiple vulnerabilities in Samba. These flaws, identified as CVE-2026-58216, CVE-2026-58218, CVE-2026-58221, CVE-2026-58222, CVE-2026-58224, and CVE-2026-6949, affect various versions of the Samba software, specifically versions 4.23.x prior to 4.23.9, 4.24.x prior to 4.24.4, and all versions prior to 4.22.10. While the advisory does not specify an active threat actor or observed exploitation campaigns, the vulnerabilities are critical as they could lead to remote denial of service, unauthorized access to sensitive data, and the circumvention of existing security mechanisms. Defenders must prioritize patching to protect their network-attached storage and domain services from potential exploitation.

## Impact

Successful exploitation of these Samba vulnerabilities could result in significant operational disruption and data compromise. Attackers could trigger a remote denial of service, rendering critical file-sharing services unavailable. Furthermore, the flaws enable unauthorized access to sensitive data stored on Samba shares, leading to data breaches and privacy violations. The ability to bypass security policies could allow attackers to escalate privileges or gain persistent access, undermining the overall security posture of an organization. No specific victim counts or targeted sectors were provided, but any organization utilizing vulnerable Samba versions is at risk.

## Recommendation

* Immediately apply the security patches provided by the vendor for CVE-2026-58216, CVE-2026-58218, CVE-2026-58221, CVE-2026-58222, CVE-2026-58224, and CVE-2026-6949 as referenced in the Samba security bulletins.
* Upgrade Samba installations to versions 4.23.9 or later, 4.24.4 or later, or 4.22.10 or later, depending on the current major version, to mitigate the identified risks.
* Consult the official Samba security bulletins provided in the references section for detailed patching instructions and additional mitigation advice specific to each vulnerability.
