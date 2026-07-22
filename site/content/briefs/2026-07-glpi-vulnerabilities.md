---
title: Multiple Vulnerabilities in GLPI
slug: 2026-07-glpi-vulnerabilities
description: Multiple vulnerabilities have been discovered in GLPI, specifically affecting versions 11.0.x prior to 11.0.8 and all versions prior to 10.0.26, which allow an attacker to compromise data confidentiality and integrity, and bypass security policies.
date: "2026-07-22T14:51:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - web-application
  - glpi
  - data-breach
  - data-integrity
  - security-policy-bypass
vendors:
  - GLPI-Project
products:
  - GLPI < 10.0.26
  - GLPI 11.0.x < 11.0.8
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Destruction
    evidence: Atteinte à l'intégrité des données
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Destruction
    evidence: Atteinte à la confidentialité des données
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Contournement de la politique de sécurité
    confidence_band: med
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0909/
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-2hf7-pw75-7wcp
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-3vhr-7p54-cqhw
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-p68f-rv24-mc54
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-xm3v-3g6q-g9q8
  - https://www.cve.org/CVERecord?id=CVE-2026-45801
  - https://www.cve.org/CVERecord?id=CVE-2026-53627
  - https://www.cve.org/CVERecord?id=CVE-2026-53628
  - https://www.cve.org/CVERecord?id=CVE-2026-55217
---

CERT-FR has issued an advisory regarding multiple vulnerabilities identified in GLPI, an open-source IT asset management software. These vulnerabilities, tracked as CVE-2026-45801, CVE-2026-53627, CVE-2026-53628, and CVE-2026-55217, were disclosed on July 22, 2026, following bulletins from GLPI-Project. The affected versions include GLPI 11.0.x prior to 11.0.8 and all GLPI versions prior to 10.0.26. Successful exploitation of these flaws could lead to severe consequences, including unauthorized access to sensitive information (data confidentiality compromise), unauthorized modification or corruption of data (data integrity compromise), and the circumvention of existing security policies within the GLPI application. Organizations using vulnerable GLPI instances are at risk of significant data breaches and operational disruption.

## Attack Chain

1. An attacker identifies an internet-facing or internal GLPI instance running a vulnerable version (11.0.x prior to 11.0.8 or prior to 10.0.26).
2. The attacker performs reconnaissance to understand the specific GLPI deployment and potential entry points.
3. Leveraging publicly available information or reverse-engineering, the attacker crafts malicious HTTP requests tailored to exploit one or more of the identified vulnerabilities (CVE-2026-45801, CVE-2026-53627, CVE-2026-53628, CVE-2026-55217).
4. These specially crafted requests are sent to the vulnerable GLPI web server, attempting to trigger the underlying flaw.
5. Successful exploitation leads to the circumvention of GLPI's internal security policies and access controls, granting the attacker unauthorized privileges or access to restricted functionalities.
6. The attacker then leverages this unauthorized access to view sensitive data stored within the GLPI application, compromising data confidentiality.
7. Alternatively, or in conjunction, the attacker may modify or corrupt existing data records within GLPI, leading to a compromise of data integrity.
8. The attacker verifies the success of the data compromise (confidentiality or integrity) and the policy circumvention.

## Impact

The successful exploitation of these vulnerabilities can lead to significant impact on organizations utilizing GLPI. Attackers can gain unauthorized access to sensitive IT asset information, user details, and operational data, leading to a breach of data confidentiality. Furthermore, the ability to modify data could result in corrupted inventory records, altered service requests, or manipulated user credentials, severely impacting data integrity and potentially disrupting IT operations. The circumvention of security policies means that existing protective measures within GLPI could be bypassed, leaving the system vulnerable to further unauthorized actions and potentially wider network access depending on the GLPI deployment.

## Recommendation

* Immediately apply the security patches provided by GLPI-Project to upgrade affected GLPI instances to version 11.0.8 or later for the 11.0.x branch, or 10.0.26 or later for the 10.0.x branch, as detailed in the referenced GLPI security bulletins.
* Monitor web server access logs for unusual request patterns, especially those targeting GLPI URLs, that might indicate exploitation attempts for CVE-2026-45801, CVE-2026-53627, CVE-2026-53628, and CVE-2026-55217.
* Review GLPI audit logs for unauthorized data access, modification events, or unexpected changes in user permissions that could signal a security policy bypass or data integrity compromise.
