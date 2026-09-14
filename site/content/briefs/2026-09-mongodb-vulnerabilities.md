---
title: Multiple Critical Vulnerabilities in MongoDB Drivers and Core Server
slug: 2026-09-mongodb-vulnerabilities
description: Multiple vulnerabilities across MongoDB drivers and the Core Server identified on September 10-11, 2026, pose risks of remote denial-of-service, unauthorized data access, and integrity compromise.
date: "2026-09-14T19:03:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - database
  - patch-management
vendors:
  - MongoDB
products:
  - C Driver (< 1.30.10, < 2.5.3)
  - C# Driver (< 3.11.2)
  - C++ Driver (< 4.5.3)
  - Core Server (< 7.0.43, < 8.0.32, < 8.3.11, < 9.1.0-rc0)
  - Go Driver (< 1.17.10, < 2.9.1)
  - Java Driver (< 5.11.1)
  - PHP Driver (< 1.21.5, < 2.4.2)
  - PHP Laravel MongoDB Integration (< 5.11.0)
  - Python Driver (< 4.18.1)
  - Ruby Driver (< 2.26.0)
  - Rust Driver (< 3.9.1)
cves:
  - id: CVE-2026-88022
    cvss: 7.7
    epss: 0.00297
  - id: CVE-2026-88036
    cvss: 8.3
    epss: 0.00259
  - id: CVE-2026-89099
    cvss: 7.5
    epss: 0.00182
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1169/
  - https://jira.mongodb.org/browse/SERVER-134063
  - https://www.cve.org/CVERecord?id=CVE-2026-88022
  - https://www.cve.org/CVERecord?id=CVE-2026-89099
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade all affected MongoDB Core Server and driver packages to the patched versions documented in the referenced security bulletins.
      owner: IT Operations
      addresses: All CVEs listed in CERT-FR-2026-AVI-1169
      evidence: Source documentation mandates upgrades to patched versions.
---

On September 10 and 11, 2026, MongoDB released a series of security bulletins addressing multiple vulnerabilities affecting the MongoDB Core Server and a wide range of language-specific drivers. The identified vulnerabilities include issues that can lead to remote denial-of-service (DoS), unauthorized disclosure or alteration of data, and bypasses of established security policies. The scope of the vulnerability set is extensive, impacting the C, C#, C++, Go, Java, PHP, Python, Ruby, and Rust drivers, alongside several Core Server versions (7.0.x, 8.0.x, 8.3.x, and 9.1.0-rc0). Organizations utilizing these drivers or managing MongoDB instances are urged to evaluate their current deployments against the patched versions listed in the vendor documentation. The vulnerability set is tracked under various identifiers, including CVE-2026-88022 through CVE-2026-88036, and CVE-2026-89099.

## Impact

Successful exploitation of these vulnerabilities could result in significant operational disruption via service outages, loss of sensitive data confidentiality, and corruption of database records. Given the widespread use of MongoDB across diverse sectors, these vulnerabilities present a high risk to enterprise database integrity and availability.

## Recommendation

- Perform an immediate audit of all internal MongoDB infrastructure and application environments to identify usage of the affected driver versions.
- Upgrade all affected MongoDB drivers to the versions specified in the vendor's security bulletins to mitigate potential exploitation.
- Upgrade MongoDB Core Server instances to the following minimum safe versions: 7.0.43, 8.0.32, or 8.3.11.
- Monitor database logs for unusual connection patterns or anomalous administrative activities that may suggest attempts to exploit security policy bypasses.
