---
title: Multiple Vulnerabilities in MongoDB Core Server and Compass
slug: 2026-07-mongodb-multi-vulnerabilities
description: Numerous vulnerabilities across MongoDB Core Server and Compass, identified as CVE-2026-13055 through CVE-2026-13078, CVE-2026-14881, and CVE-2026-9737, enable attackers to bypass security policies and induce denial-of-service conditions, necessitating immediate patching.
date: "2026-07-24T13:25:53Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - database
  - mongodb
vendors:
  - MongoDB
products:
  - Compass (< 1.49.7)
  - Core Server (7.0.x < 7.0.39)
  - Core Server (8.0.x < 8.0.28)
  - Core Server (8.2.x < 8.2.12)
  - Core Server (8.3.x < 8.3.7)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Un attaquant de provoquer un contournement de la politique de sécurité
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Un attaquant de provoquer un [...] déni de service
    confidence_band: high
cves:
  - id: CVE-2026-14881
    cvss: 7.8
    epss: 0.00194
  - id: CVE-2026-13056
    cvss: 6.5
    epss: 0.00411
  - id: CVE-2026-13063
    cvss: 4.3
    epss: 0.00359
  - id: CVE-2026-13070
    cvss: 5.3
    epss: 0.00133
  - id: CVE-2026-13073
    cvss: 4.3
    epss: 0.00359
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0922/
  - https://jira.mongodb.org/browse/SERVER-123081
  - https://jira.mongodb.org/browse/SERVER-124355
  - https://jira.mongodb.org/browse/SERVER-125872
  - https://jira.mongodb.org/browse/SERVER-126247
  - https://jira.mongodb.org/browse/SERVER-127280
  - https://jira.mongodb.org/browse/SERVER-127357
  - https://jira.mongodb.org/browse/SERVER-127566
  - https://jira.mongodb.org/browse/SERVER-127661
  - https://jira.mongodb.org/browse/SERVER-127689
  - https://jira.mongodb.org/browse/SERVER-127694
  - https://jira.mongodb.org/browse/SERVER-127737
  - https://jira.mongodb.org/browse/SERVER-127831
  - https://jira.mongodb.org/browse/SERVER-128198
  - https://jira.mongodb.org/browse/SERVER-128316
  - https://jira.mongodb.org/browse/SERVER-128341
  - https://jira.mongodb.org/browse/SERVER-128362
  - https://jira.mongodb.org/browse/SERVER-128387
  - https://jira.mongodb.org/browse/SERVER-128433
  - https://jira.mongodb.org/browse/SERVER-128473
  - https://jira.mongodb.org/browse/SERVER-128494
  - https://jira.mongodb.org/browse/SERVER-128512
  - https://jira.mongodb.org/browse/SERVER-128517
  - https://jira.mongodb.org/browse/SERVER-128584
  - https://jira.mongodb.org/browse/SERVER-128832
  - https://jira.mongodb.org/browse/SERVER-129103
  - https://github.com/mongodb-js/compass/releases/tag/v1.49.7
  - https://www.cve.org/CVERecord?id=CVE-2026-13055
  - https://www.cve.org/CVERecord?id=CVE-2026-13056
  - https://www.cve.org/CVERecord?id=CVE-2026-13057
  - https://www.cve.org/CVERecord?id=CVE-2026-13058
  - https://www.cve.org/CVERecord?id=CVE-2026-13059
  - https://www.cve.org/CVERecord?id=CVE-2026-13060
  - https://www.cve.org/CVERecord?id=CVE-2026-13061
  - https://www.cve.org/CVERecord?id=CVE-2026-13062
  - https://www.cve.org/CVERecord?id=CVE-2026-13063
  - https://www.cve.org/CVERecord?id=CVE-2026-13064
  - https://www.cve.org/CVERecord?id=CVE-2026-13065
  - https://www.cve.org/CVERecord?id=CVE-2026-13066
  - https://www.cve.org/CVERecord?id=CVE-2026-13067
  - https://www.cve.org/CVERecord?id=CVE-2026-13068
  - https://www.cve.org/CVERecord?id=CVE-2026-13069
  - https://www.cve.org/CVERecord?id=CVE-2026-13070
  - https://www.cve.org/CVERecord?id=CVE-2026-13071
  - https://www.cve.org/CVERecord?id=CVE-2026-13072
  - https://www.cve.org/CVERecord?id=CVE-2026-13073
  - https://www.cve.org/CVERecord?id=CVE-2026-13074
  - https://www.cve.org/CVERecord?id=CVE-2026-13075
  - https://www.cve.org/CVERecord?id=CVE-2026-13076
  - https://www.cve.org/CVERecord?id=CVE-2026-13077
  - https://www.cve.org/CVERecord?id=CVE-2026-13078
  - https://www.cve.org/CVERecord?id=CVE-2026-14881
  - https://www.cve.org/CVERecord?id=CVE-2026-9737
iocs:
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-123081
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-124355
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-125872
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-126247
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127280
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127357
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127566
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127661
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127689
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127694
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127737
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-127831
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128198
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128316
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128341
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128362
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128387
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128433
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128473
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128494
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128512
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128517
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128584
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-128832
  - type: url
    value: https://jira.mongodb.org/browse/SERVER-129103
  - type: url
    value: https://github.com/mongodb-js/compass/releases/tag/v1.49.7
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13055
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13056
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13057
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13058
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13059
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13060
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13061
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13062
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13063
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13064
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13065
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13066
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13067
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13068
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13069
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13070
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13071
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13072
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13073
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13074
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13075
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13076
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13077
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-13078
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-14881
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-9737
ioc_counts:
  url: 52
---

CERT-FR has issued an advisory regarding multiple vulnerabilities discovered in MongoDB products, specifically affecting MongoDB Core Server and MongoDB Compass. These 26 distinct vulnerabilities, ranging from CVE-2026-13055 to CVE-2026-13078, CVE-2026-14881, and CVE-2026-9737, were initially detailed in MongoDB security bulletins on July 22, 2026. While no specific threat actor or active exploitation campaign has been identified, these flaws pose significant risks. Attackers could leverage these vulnerabilities to circumvent security policies, trigger denial-of-service (DoS) conditions, and exploit other unspecified security problems. Organizations using affected versions of MongoDB should prioritize applying the recommended patches to mitigate potential risks to their data and service availability.

## Impact

Successful exploitation of these vulnerabilities could lead to significant damage. An attacker could bypass existing security policies, potentially gaining unauthorized access to sensitive data or functionality within the MongoDB environment. The denial-of-service vulnerabilities could allow an attacker to disrupt the availability of MongoDB databases and applications relying on them, leading to operational outages and financial losses. Furthermore, the presence of "unspecified security issues" suggests that other, potentially more severe, impacts may be possible depending on the specific vulnerability and how it is exploited, including data corruption or unauthorized data modification.

## Recommendation

* Refer to the MongoDB security bulletins referenced in this brief (e.g., SERVER-123081, SERVER-124355) and apply all necessary patches to update affected MongoDB Core Server and Compass instances to the patched versions.
* Patch CVE-2026-13055 through CVE-2026-13078, CVE-2026-14881, and CVE-2026-9737 on all affected MongoDB installations immediately.
* Ensure that MongoDB Compass is updated to version 1.49.7 or later.
* Upgrade MongoDB Core Server to versions 7.0.39 or later, 8.0.28 or later, 8.2.12 or later, or 8.3.7 or later, depending on the major version deployed.
