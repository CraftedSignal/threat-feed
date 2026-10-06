---
title: CUPS Denial of Service Vulnerability
slug: 2026-10-cups-dos
description: A local attacker can exploit a vulnerability in the Common Unix Printing System (CUPS) to cause a denial-of-service condition affecting the printing service.
date: "2026-10-06T12:43:46Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:openprinting:cups:*:*:*:*:*:*:*:*
  - cpe:2.3:a:openprinting:libppd:*:*:*:*:*:*:*:*
  - cpe:2.3:a:openprinting:libppd:2.1:beta1*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - linux
  - cups
vendors:
  - OpenPrinting
products:
  - CUPS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in CUPS ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-47175
    cvss: 8.6
    epss: 0.63607
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3742
---

The Common Unix Printing System (CUPS) is affected by a vulnerability that allows a local attacker to cause a denial-of-service (DoS) condition. The issue involves improper handling of service requests, which can be manipulated by an attacker with local access to disrupt printing operations. This vulnerability is tracked as CVE-2024-47175. While the impact is limited to the availability of the printing service on the affected Linux-based system, it necessitates timely patching to ensure system stability and service uptime. Defenders should monitor for unexpected restarts or crashes of the CUPS service that might indicate exploitation attempts within their local environment.

## Impact

Successful exploitation results in the disruption of the printing service on the target system. This impacts local users and applications relying on CUPS for document output. Given that this requires local access, the scope is primarily limited to multi-user Linux systems or shared workstations where an attacker has achieved a low-privilege local account.

## Recommendation

Prioritize the application of vendor-supplied security updates for the CUPS package across all Linux distributions. Verify that the current version of the CUPS software is no longer vulnerable to CVE-2024-47175 by checking the package manager repositories for the latest security patches.
