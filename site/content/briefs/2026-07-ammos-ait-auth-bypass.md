---
title: Unauthenticated API Access in AMMOS Instrument Toolkit DSN Interface
slug: 2026-07-ammos-ait-auth-bypass
description: The AMMOS Instrument Toolkit (AIT) DSN Interface prior to version 2.2.2 contains a missing authentication vulnerability in the Space Link Extension interface manager, allowing unauthenticated attackers to invoke sensitive API routes.
date: "2026-07-29T16:20:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - api-security
  - authentication-bypass
  - cve-2026-60113
vendors:
  - NASA
products:
  - AMMOS Instrument Toolkit (AIT) Deep Space Network (DSN) Interface
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The AMMOS Instrument Toolkit (AIT) DSN Interface before 2.2.2 contains a missing authentication vulnerability in the Space Link Extension (SLE) interface manager that allows unauthenticated network attackers to access seven unprotected API routes by sending direct HTTP requests with no credentials.
    confidence_band: high
cves:
  - id: CVE-2026-60113
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60113
---

The AMMOS Instrument Toolkit (AIT) Deep Space Network (DSN) Interface, specifically versions prior to 2.2.2, contains a critical missing authentication vulnerability within its Space Link Extension (SLE) interface manager. This vulnerability stems from the application's failure to enforce authentication controls on seven specific API routes. An unauthenticated network attacker can exploit this flaw by sending direct, unauthenticated HTTP requests to the target interface. Successful exploitation grants the attacker the ability to manage Deep Space Network communication sessions, retrieve sensitive telemetry frame data, and inject arbitrary frames into active spacecraft links. Given the role of this toolkit in deep space communication, this flaw poses a high risk to both the confidentiality and integrity of command-and-control links between ground segments and remote space assets.

## Impact

The vulnerability allows for the unauthorized control of Deep Space Network communication sessions, potential exfiltration of proprietary or sensitive spacecraft telemetry data, and the injection of malicious or arbitrary frames into mission-critical communication links. This could lead to a loss of operational control, data interception, or potential interference with spacecraft operations.

## Recommendation

- Upgrade the AMMOS Instrument Toolkit (AIT) DSN Interface to version 2.2.2 or later immediately to address the missing authentication vulnerability tracked as CVE-2026-60113.
- Implement network segmentation and access control lists (ACLs) to restrict access to the SLE interface manager endpoints to only authorized ground segment IP addresses.
- Monitor web server access logs for anomalous requests targeting SLE interface API endpoints, particularly those originating from unauthorized or external network segments.
- Audit existing API configurations to ensure that authentication and authorization middleware are correctly applied to all discovered service endpoints.
