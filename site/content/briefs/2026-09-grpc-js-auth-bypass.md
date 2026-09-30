---
title: Improper Authentication in @grpc/grpc-js
slug: 2026-09-grpc-js-auth-bypass
description: The @grpc/grpc-js library contains an authentication bypass vulnerability (CVE-2026-101916) where unauthorized client certificates may be treated as authorized when requireClientCertificate is disabled.
date: "2026-09-30T16:27:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:grpc:grpc-js:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - grpc
  - rbac
  - authentication-bypass
vendors:
  - gRPC
products:
  - '@grpc/grpc-js (< 1.13.6, >= 1.14.0, < 1.14.5)'
  - '@grpc/grpc-js-xds (< 1.13.6)'
cves:
  - id: CVE-2026-101916
    cvss: 7.4
    epss: 0.00208
references:
  - https://github.com/advisories/GHSA-m9gg-hp2v-232j
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101916
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Upgrade @grpc/grpc-js to 1.13.6 or 1.14.5
      owner: Development
      due: 48h
      evidence: Source explicitly states vulnerability is fixed in 1.13.6 and 1.14.5.
  mitigation_plan:
    - priority: immediate
      action: Set requireClientCertificate to true in server credential configurations
      owner: Development
      addresses: CVE-2026-101916
      evidence: Workaround documentation provided in source.
---

The @grpc/grpc-js library (CVE-2026-101916) exhibits a flaw in how it handles client certificate verification within the getAuthContext method. When developers configure server credentials with the requireClientCertificate option set to false, the library fails to properly distinguish between authorized and unauthorized client certificates in the returned authentication context. This vulnerability is particularly critical for applications that rely on the output of getAuthContext for Role-Based Access Control (RBAC) decisions. The issue is documented to affect the @grpc/grpc-js-xds integration, where specific configurations of DownstreamTlsContext can inadvertently enable this bypass, potentially allowing unauthenticated or unauthorized clients to gain access to protected resources. Defenders should prioritize updating affected packages to versions 1.13.6 or 1.14.5 to remediate this logic flaw.

## Impact

The vulnerability allows for potential authentication bypass in gRPC-based services. If an application utilizes getAuthContext to enforce security policies, unauthorized parties may masquerade as authorized users. The scope of impact includes any infrastructure utilizing @grpc/grpc-js or @grpc/grpc-js-xds for internal or external service-to-service authentication. If exploited, an attacker could gain unauthorized access to backend services protected by RBAC, potentially leading to data exfiltration or unauthorized execution of RPC methods.

## Recommendation

* Update @grpc/grpc-js and @grpc/grpc-js-xds dependencies to version 1.13.6 or 1.14.5 immediately to patch CVE-2026-101916.
* Audit application code for usage of getAuthContext to ensure it is not relied upon for security-critical RBAC decisions without explicit client certificate verification.
* For configurations that cannot be patched immediately, set the requireClientCertificate option to true in the gRPC server credentials.
* For @grpc/grpc-js-xds users, set the require_client_certificate field to true within the DownstreamTlsContext in the xDS configuration to enforce certificate validation.
