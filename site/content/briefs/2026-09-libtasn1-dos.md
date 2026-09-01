---
title: Denial of Service Vulnerability in libtasn1
slug: 2026-09-libtasn1-dos
description: A vulnerability in the libtasn1 library tracked as CVE-2024-11111 allows a remote, anonymous attacker to cause a Denial of Service condition, potentially impacting applications that rely on the library for ASN.1 structure processing.
date: "2026-09-01T12:04:41Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gnu:libtasn1:*:*:*:*:*:*:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
vendors:
  - GNU
products:
  - libtasn1 (< 131.0.6778.69)
cves:
  - id: CVE-2024-11111
    cvss: 4.3
    epss: 0.00436
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3116
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Upgrade libtasn1 to 131.0.6778.69 or later
      owner: IT Operations
      addresses: CVE-2024-11111
      evidence: Source reporting identifies CVE-2024-11111 as the cause for potential DoS.
---

A vulnerability identified in the libtasn1 library, a C library used for Abstract Syntax Notation One (ASN.1) structure management, may be exploited by a remote, anonymous attacker to trigger a Denial of Service (DoS) condition. The flaw affects the processing of ASN.1 data, where specifically crafted inputs can cause the library to enter an unstable state, leading to application crashes or service disruptions for dependent services. Because libtasn1 is widely utilized by various software products for security and data parsing tasks, this vulnerability poses a risk to system availability. Defenders should monitor for unexpected application crashes or service restarts in processes linked to libtasn1.

## Impact

Successful exploitation results in a Denial of Service, causing application instability or service outages for systems relying on the libtasn1 library. This can degrade availability for critical infrastructure components that process network or security protocol data.

## Recommendation

Prioritized actions for security operations and IT teams:
- Inventory systems and applications that utilize libtasn1 to identify exposure to CVE-2024-11111.
- Apply patches provided by the GNU project or upstream maintainers as soon as they become available for the distribution or product in use.
- Monitor logs for repeated service crashes (e.g., core dumps or application-level exit codes) in services that handle external ASN.1 encoded traffic.
