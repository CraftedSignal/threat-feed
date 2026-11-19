---
brief_id: brief-2026-11-19-miren-runtime-auth-bypass-ghsa-8fh7-7q4q-cq52
event_id: brief-2026-11-19-miren-runtime-auth-bypass-ghsa-8fh7-7q4q-cq52
revision: 1
activity_at: "2026-11-19T04:09:08Z"
title: 'Miren Runtime: RPC layer authentication bypass (CVE-2026-75521)'
slug: 2026-11-miren-runtime-auth-bypass-ghsa-8fh7-7q4q-cq52
description: Miren Runtime versions prior to 0.11.1 contain an authentication bypass vulnerability in the RPC layer, present when a cluster CA is configured, which allows attackers to gain cluster superuser access by presenting a forged, self-signed TLS certificate.
date: "2026-11-19T04:09:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:mirendev:runtime:*:*:*:*:*:*:*:*
vendors:
  - mirendev
products:
  - runtime
cves:
  - id: CVE-2026-75521
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-8fh7-7q4q-cq52
  - https://cveawg.mitre.org/api/cve/CVE-2026-75521
---

## Overview
Miren Runtime (prior to 0.11.1) contains an authentication bypass vulnerability in the QUIC/HTTP3 RPC server (default port 8443). The vulnerability occurs when a cluster Certificate Authority (CA) is configured, as the listener uses 'tls.RequestClientCert' but fails to verify that presented client certificates chain to the configured CA. The RPC layer instead derives caller identity from the CommonName of unverified certificates, granting cluster superuser access to any party that can reach the RPC listener and present a self-signed certificate with an issuer DN matching the cluster CA.

## Impact
Successful exploitation allows an unauthenticated attacker with network access to the RPC listener to gain full cluster superuser privileges, enabling the disclosure, modification, or disruption of applications, sandboxes, disks, credentials, and other managed resources. Deployments that expose port 8443 beyond a trusted network are at higher risk of remote exploitation.

## Recommendation
- Upgrade to Miren Runtime version 0.11.1 or later.
- As a containment measure until patching, restrict network access to port 8443 to trusted management networks only; avoid exposing the port to untrusted networks (e.g., 0.0.0.0/0).
- Due to the potential for unauthorized access, Miren recommends redeploying applications and rotating credentials referenced in environment variables. A read-only audit script is available at https://github.com/mirendev/runtime/tree/089582a132f7fc1e1d5b5c0aee1e0911535fed53/scripts/security/audit-exposure.
