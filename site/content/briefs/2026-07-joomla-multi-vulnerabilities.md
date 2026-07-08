---
title: Multiple Vulnerabilities Discovered in Joomla! CMS
slug: 2026-07-joomla-multi-vulnerabilities
description: Multiple vulnerabilities, including several Cross-Site Scripting (XSS) flaws and incorrect access control issues, have been discovered in Joomla! versions 6.x prior to 6.1.2 and 5.x prior to 5.4.7, which could allow an attacker to bypass security policies, compromise data confidentiality and integrity, and perform remote indirect code injection.
date: "2026-07-08T14:15:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - xss
  - access-control
  - cms
  - joomla
vendors:
  - Joomla!
products:
  - Joomla! (versions 6.x antérieures à 6.1.2)
  - Joomla! (versions antérieures à 5.4.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: injection de code indirecte à distance (XSS)
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: atteinte à la confidentialité des données
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: atteinte à l'intégrité des données
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Contournement de la politique de sécurité
    confidence_band: med
cves:
  - id: CVE-2026-48949
  - id: CVE-2026-48954
  - id: CVE-2026-48948
  - id: CVE-2026-48955
  - id: CVE-2026-48957
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0847/
  - https://developer.joomla.org/security-centre/1055-20260701-core-incorrect-access-control-in-com-media-webservice-endpoints.html
  - https://developer.joomla.org/security-centre/1056-20260702-core-incorrect-access-control-in-com-contact-vcf-download.html
  - https://developer.joomla.org/security-centre/1057-20260703-core-xss-in-mfa-method-management.html
  - https://developer.joomla.org/security-centre/1058-20260704-core-xss-in-com-templates.html
  - https://developer.joomla.org/security-centre/1059-20260705-core-xss-in-various-modalreturn-layouts.html
  - https://developer.joomla.org/security-centre/1060-20260706-core-xss-in-com-installer.html
  - https://developer.joomla.org/security-centre/1061-20260707-core-xss-in-the-generic-image-output-layout.html
  - https://developer.joomla.org/security-centre/1062-20260708-core-xss-through-language-overrides.html
  - https://developer.joomla.org/security-centre/1063-20260709-core-incorrect-access-control-in-com-workflow.html
  - https://developer.joomla.org/security-centre/1064-20260710-core-incorrect-access-control-in-com-modules.html
  - https://developer.joomla.org/security-centre/1065-20260711-core-incorrect-access-control-in-com-privacy-webservice-endpoints.html
  - https://developer.joomla.org/security-centre/1066-20260712-core-incorrect-access-control-in-com-fields-webservice-endpoints.html
  - https://www.cve.org/CVERecord?id=CVE-2026-48947
  - https://www.cve.org/CVERecord?id=CVE-2026-48948
  - https://www.cve.org/CVERecord?id=CVE-2026-48949
  - https://www.cve.org/CVERecord?id=CVE-2026-48950
  - https://www.cve.org/CVERecord?id=CVE-2026-48951
  - https://www.cve.org/CVERecord?id=CVE-2026-48952
  - https://www.cve.org/CVERecord?id=CVE-2026-48953
  - https://www.cve.org/CVERecord?id=CVE-2026-48954
  - https://www.cve.org/CVERecord?id=CVE-2026-48955
  - https://www.cve.org/CVERecord?id=CVE-2026-48956
  - https://www.cve.org/CVERecord?id=CVE-2026-48957
  - https://www.cve.org/CVERecord?id=CVE-2026-48958
iocs:
  - type: url
    value: https://developer.joomla.org/security-centre/1055-20260701-core-incorrect-access-control-in-com-media-webservice-endpoints.html
  - type: url
    value: https://developer.joomla.org/security-centre/1056-20260702-core-incorrect-access-control-in-com-contact-vcf-download.html
  - type: url
    value: https://developer.joomla.org/security-centre/1057-20260703-core-xss-in-mfa-method-management.html
  - type: url
    value: https://developer.joomla.org/security-centre/1058-20260704-core-xss-in-com-templates.html
  - type: url
    value: https://developer.joomla.org/security-centre/1059-20260705-core-xss-in-various-modalreturn-layouts.html
  - type: url
    value: https://developer.joomla.org/security-centre/1060-20260706-core-xss-in-com-installer.html
  - type: url
    value: https://developer.joomla.org/security-centre/1061-20260707-core-xss-in-the-generic-image-output-layout.html
  - type: url
    value: https://developer.joomla.org/security-centre/1062-20260708-core-xss-through-language-overrides.html
  - type: url
    value: https://developer.joomla.org/security-centre/1063-20260709-core-incorrect-access-control-in-com-workflow.html
  - type: url
    value: https://developer.joomla.org/security-centre/1064-20260710-core-incorrect-access-control-in-com-modules.html
  - type: url
    value: https://developer.joomla.org/security-centre/1065-20260711-core-incorrect-access-control-in-com-privacy-webservice-endpoints.html
  - type: url
    value: https://developer.joomla.org/security-centre/1066-20260712-core-incorrect-access-control-in-com-fields-webservice-endpoints.html
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48947
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48948
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48949
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48950
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48951
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48952
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48953
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48954
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48955
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48956
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48957
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-48958
ioc_counts:
  url: 24
---

On July 8, 2026, the French National Cybersecurity Agency (ANSSI) CERT-FR issued an advisory detailing multiple vulnerabilities impacting the Joomla! Content Management System. These flaws affect Joomla! 6.x versions earlier than 6.1.2 and Joomla! 5.x versions earlier than 5.4.7. The vulnerabilities encompass various Cross-Site Scripting (XSS) issues and several instances of incorrect access control within components like `com-media-webservice-endpoints`, `com-contact-vcf-download`, `com-workflow`, `com-modules`, `com-privacy-webservice-endpoints`, and `com-fields-webservice-endpoints`. Successful exploitation could lead to breaches of data confidentiality, compromises of data integrity, remote indirect code injection, and a general bypass of security policies, potentially granting unauthorized access or control over the affected Joomla! instance and its data. Organizations running vulnerable versions of Joomla! are urged to apply patches immediately to mitigate these risks.

## Attack Chain

1. An unauthenticated or low-privileged attacker identifies a vulnerable Joomla! instance.
2. The attacker crafts a malicious request targeting specific Joomla! components, such as `com-templates` or `com-installer`, containing XSS payloads.
3. The crafted request leverages the XSS vulnerability (e.g., CVE-2026-48949, CVE-2026-48950, CVE-2026-48951, CVE-2026-48952, CVE-2026-48953, CVE-2026-48954) to inject malicious client-side script into web pages viewed by other users, including administrators.
4. Alternatively, the attacker exploits incorrect access control vulnerabilities (e.g., CVE-2026-48947, CVE-2026-48948, CVE-2026-48955, CVE-2026-48956, CVE-2026-48957, CVE-2026-48958) in various webservice endpoints or components.
5. Through XSS, the attacker compromises legitimate user sessions, potentially stealing cookies, session tokens, or performing actions on behalf of the victim.
6. Through incorrect access control, the attacker gains unauthorized access to sensitive data, modifies system configurations, or manipulates content, leading to data confidentiality and integrity breaches.

## Impact

The identified vulnerabilities could result in significant damage to affected organizations. Successful exploitation of the Cross-Site Scripting (XSS) flaws can lead to session hijacking, defacement, or redirection, potentially exposing administrative credentials or sensitive user data. The incorrect access control vulnerabilities could allow unauthorized users to view, modify, or delete critical information, leading to data breaches or integrity compromises. While no specific victim count or targeted sectors were detailed in the advisory, any organization utilizing vulnerable Joomla! versions is at risk of unauthorized data access, website defacement, and potential regulatory non-compliance due to data exposure.

## Recommendation

* Prioritize patching all affected Joomla! installations to versions 6.1.2 or later, or 5.4.7 or later, as recommended in the CERTFR-2026-AVI-0847 advisory.
* Review web server access logs for unusual requests containing script-like characters in parameters, especially for URLs related to `com-templates`, `com-installer`, or other components mentioned in the Joomla! security bulletins.
* Implement a robust Web Application Firewall (WAF) to detect and block malicious requests attempting to exploit CVE-2026-48949, CVE-2026-48950, CVE-2026-48951, CVE-2026-48952, CVE-2026-48953, and CVE-2026-48954.
* Regularly back up Joomla! databases and file systems to ensure data integrity can be restored in case of a successful exploit leading to data corruption or loss.
