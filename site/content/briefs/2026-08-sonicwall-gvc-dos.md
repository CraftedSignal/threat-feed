---
title: Denial of Service Vulnerability in SonicWall Global VPN Client
slug: 2026-08-sonicwall-gvc-dos
description: A vulnerability (CVE-2026-66151) in SonicWall Global VPN Client versions prior to 5.0.0.2008 allows remote attackers to trigger a denial of service condition.
date: "2026-08-10T13:25:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - SonicWall
products:
  - Global VPN Client
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Une vulnérabilité a été découverte dans SonicWall Global VPN Client. Elle permet à un attaquant de provoquer un déni de service.
    confidence_band: high
cves:
  - id: CVE-2026-66151
    epss: 0.00157
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0990/
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0010
  - https://www.cve.org/CVERecord?id=CVE-2026-66151
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding a denial of service (DoS) vulnerability, tracked as CVE-2026-66151, affecting SonicWall Global VPN Client. This flaw impacts all versions of the client prior to 5.0.0.2008. The vulnerability allows an unauthenticated remote attacker to disrupt the availability of the VPN client, effectively preventing users from establishing secure connections to corporate resources. Organizations utilizing this software should prioritize upgrading to the patched version, 5.0.0.2008 or later, as specified in SonicWall security bulletin SNWLID-2026-0010.

## Impact

Successful exploitation results in a denial of service for the SonicWall Global VPN Client application. This disruption impacts connectivity for remote workers and branch offices reliant on the client for secure network access. While the advisory does not report widespread exploitation, organizations must treat this as a risk to business continuity for any remote-access infrastructure running outdated client versions.

## Recommendation

* Upgrade all instances of SonicWall Global VPN Client to version 5.0.0.2008 or later immediately.
* Consult the vendor security bulletin SNWLID-2026-0010 for specific deployment guidance and patch verification procedures.
