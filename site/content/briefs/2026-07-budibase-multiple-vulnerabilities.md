---
title: 'Budibase: Multiple Vulnerabilities'
slug: 2026-07-budibase-multiple-vulnerabilities
description: Multiple vulnerabilities in Budibase allow an attacker to gain elevated privileges, perform SQL injection, bypass security measures, take over user accounts, manipulate or disclose data, and trigger a denial-of-service condition, enabling various malicious activities impacting data integrity, confidentiality, and system availability.
date: "2026-07-23T10:25:34Z"
lastmod: "2026-07-24T21:50:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:budibase:budibase:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - sql-injection
  - privilege-escalation
  - defense-evasion
  - data-exfiltration
  - denial-of-service
vendors:
  - Budibase
products:
  - Budibase
  - npm/@budibase/server <= 3.39.14
  - '@budibase/server (<= 3.38.1)'
  - account.budibase.app
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein Angreifer kann mehrere Schwachstellen in Budibase ausnutzen, um erweiterte Berechtigungen zu erlangen, SQL-Injection durchzuführen, Sicherheitsmaßnahmen zu umgehen, Konten zu übernehmen, Daten zu manipulieren oder offenzulegen sowie einen Denial-of-Service-Zustand auszulösen.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Ein Angreifer kann mehrere Schwachstellen in Budibase ausnutzen, um erweiterte Berechtigungen zu erlangen, SQL-Injection durchzuführen, Sicherheitsmaßnahmen zu umgehen, Konten zu übernehmen, Daten zu manipulieren oder offenzulegen sowie einen Denial-of-Service-Zustand auszulösen.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Ein Angreifer kann mehrere Schwachstellen in Budibase ausnutzen, um erweiterte Berechtigungen zu erlangen, SQL-Injection durchzuführen, Sicherheitsmaßnahmen zu umgehen, Konten zu übernehmen, Daten zu manipulieren oder offenzulegen sowie einen Denial-of-Service-Zustand auszulösen.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Ein Angreifer kann mehrere Schwachstellen in Budibase ausnutzen, um erweiterte Berechtigungen zu erlangen, SQL-Injection durchzuführen, Sicherheitsmaßnahmen zu umgehen, Konten zu übernehmen, Daten zu manipulieren oder offenzulegen sowie einen Denial-of-Service-Zustand auszulösen.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein Angreifer kann mehrere Schwachstellen in Budibase ausnutzen, um erweiterte Berechtigungen zu erlangen, SQL-Injection durchzuführen, Sicherheitsmaßnahmen zu umgehen, Konten zu übernehmen, Daten zu manipulieren oder offenzulegen sowie einen Denial-of-Service-Zustand auszulösen.
    confidence_band: high
cves:
  - id: CVE-2026-54353
    cvss: 8.5
    epss: 0.00202
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2483
  - https://github.com/advisories/GHSA-xg5g-26x8-cvf4
  - https://github.com/advisories/GHSA-c8vc-7pv3-g98p
  - https://github.com/advisories/GHSA-v42f-v8xc-j435
iocs:
  - type: ip
    value: 8.8.8.8
  - type: domain
    value: rebind.test
  - type: url
    value: http://rebind.test:<port>/openapi.json
  - type: domain
    value: account.budibase.app
  - type: email
    value: attacker-controlled@example.net
  - type: url
    value: https://account.budibase.app/api/v2/email
  - type: url
    value: https://account.budibase.app/api/v2/email/verification
  - type: url
    value: https://account.budibase.app/api/v2/auth/password
  - type: url
    value: https://account.budibase.app/api/v2/auth/password/verification
ioc_counts:
  domain: 2
  email: 1
  ip: 1
  url: 5
updates:
  - at: "2026-07-24T21:19:52Z"
    level: L1
    summary: new IOCs
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-xg5g-26x8-cvf4
  - at: "2026-07-24T21:22:17Z"
    level: L1
    summary: new IOCs
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-c8vc-7pv3-g98p
  - at: "2026-07-24T21:50:24Z"
    level: L2
    summary: added CVE-2026-54353
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-v42f-v8xc-j435
---

The German Federal Office for Information Security (BSI) has issued an advisory highlighting multiple critical vulnerabilities within the Budibase low-code development platform. These security flaws allow a remote attacker to achieve various severe impacts, including gaining elevated privileges, executing SQL injection attacks, bypassing existing security controls, compromising user accounts, manipulating or exfiltrating sensitive data, and causing denial-of-service conditions. While the advisory does not detail specific exploitation methods or observed in-the-wild campaigns, the breadth of potential impacts underscores the importance of prompt remediation. Organizations utilizing Budibase should be aware that successful exploitation could lead to significant data breaches, unauthorized system access, and operational disruption. The vulnerabilities affect Budibase across its various deployments, posing risks to data integrity, confidentiality, and system availability. This advisory serves as a warning for defenders to prioritize updates to prevent potential attacks.

## Impact

Successful exploitation of these multiple vulnerabilities in Budibase can lead to significant compromise across several fronts. Attackers could gain elevated privileges within the platform, allowing for unauthorized access and control. The ability to perform SQL injection attacks jeopardizes the integrity and confidentiality of stored data, potentially leading to its manipulation or complete disclosure. Furthermore, attackers can bypass security measures, facilitating account takeover and further unauthorized actions. The culmination of these issues includes the potential for extensive data breaches, where sensitive information is exfiltrated, and system unavailability due to denial-of-service conditions, severely disrupting business operations.

## Recommendation

* Update Budibase to the latest secure version immediately to remediate the multiple vulnerabilities described in this brief that affect the "Budibase" product.
