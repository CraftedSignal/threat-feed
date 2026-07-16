---
title: Denial-of-Service Vulnerability Affects ESET Endpoint Antivirus and Server Security Products (CVE-2026-6424)
slug: 2026-07-eset-dos
description: A vulnerability, identified as CVE-2026-6424, has been discovered in various ESET Endpoint Antivirus and Server Security product versions, allowing an attacker to cause a denial of service, impacting the availability of the affected systems.
date: "2026-07-16T12:58:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - endpoint-security
  - server-security
vendors:
  - ESET
products:
  - Endpoint Antivirus 12.0.x
  - Endpoint Antivirus 12.1.x
  - Endpoint Antivirus 12.2.x
  - Endpoint Antivirus 13.0.x
  - Endpoint Antivirus 13.1.x
  - Endpoint Antivirus 13.2.x
  - Server Security 12.0.x
  - Server Security 12.1.x
  - Server Security 12.2.x
  - Server Security 13.0.x
  - Server Security 13.1.x
  - Server Security 13.2.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Une vulnérabilité a été découverte dans les produits ESET. Elle permet à un attaquant de provoquer un déni de service.
    confidence_band: high
cves:
  - id: CVE-2026-6424
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0892/
  - https://support-feed.eset.com/link/15370/17380664/ca8972
  - https://www.cve.org/CVERecord?id=CVE-2026-6424
---

CERT-FR has disclosed CVE-2026-6424, a denial-of-service vulnerability affecting multiple versions of ESET's Endpoint Antivirus and Server Security products. This flaw, detailed in ESET's security bulletin ca8972, allows an attacker to disrupt the availability of systems running the affected software. Specifically, Endpoint Antivirus versions prior to 12.0.14.0, 12.1.2.0, 12.2.9.0, 13.0.5.0, 13.1.5.0, and 13.2.3.0 are impacted, alongside Server Security versions before 12.0.292.0, 12.1.407.0, 12.2.73.0, 13.0.36.0, 13.1.118.0, and 13.2.53.0. The advisory, published on July 16, 2026, urges users to apply available patches to prevent potential service interruptions. The specific mechanism for triggering the denial of service is not publicly detailed, but its impact threatens the stability and operational integrity of protected endpoints and servers.

## Attack Chain

The provided source describes a vulnerability that allows an attacker to cause a denial of service (DoS) in ESET products. However, it does not specify the steps or methods an attacker would use to trigger this DoS, nor does it detail any observed exploitation scenarios or multi-stage attack chains. Therefore, a specific attack chain cannot be constructed from the available information.

## Impact

Successful exploitation of CVE-2026-6424 leads to a denial of service on systems running vulnerable ESET Endpoint Antivirus and Server Security products. While the exact attack vector is not specified, an attacker can leverage this vulnerability to disrupt the normal operation of these security solutions, potentially rendering endpoints and servers unprotected or causing system instability. This could lead to a loss of availability for critical business functions reliant on these systems, creating operational disruptions and a temporary degradation of an organization's security posture. The scope of affected systems includes various ESET product lines, emphasizing the broad potential for disruption across different environments.

## Recommendation

* Patch CVE-2026-6424 immediately by upgrading ESET Endpoint Antivirus and Server Security products to the versions specified in ESET security bulletin ca8972.
