---
title: OpenBao Cross-Namespace Lease Revocation via Legacy sys/revoke Path
slug: 2026-05-openbao-lease-revoke
description: OpenBao versions up to 2.5.3 allow cross-namespace lease revocation by exploiting legacy sys/revoke endpoints, potentially leading to unauthorized credential access and denial of service.
date: "2026-05-28T17:38:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - acl-bypass
  - secrets-management
vendors:
  - GitHub
  - OpenBao
products:
  - openbao/openbao (Go)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/advisories/GHSA-v8v8-cm84-m686
  - https://github.com/openbao/openbao#3152
  - https://github.com/openbao/openbao@c049564
  - https://github.com/openbao/openbao/releases/tag/v2.5.4
rules:
  - title: Detect OpenBao Sys Revoke Endpoint Usage
    description: Detects usage of the OpenBao /sys/revoke endpoint, which may indicate attempts to exploit CVE-2026-45808
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555.005
    data_sources:
      - webserver
  - title: Detect OpenBao Sys Renew Endpoint Usage
    description: Detects usage of the OpenBao /sys/renew endpoint, which may indicate attempts to exploit CVE-2026-45808 by renewing leases from other namespaces
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555.005
    data_sources:
      - webserver
rules_count: 2
---

OpenBao, a secrets management solution, utilizes namespaces for multi-tenant isolation. A vulnerability exists in versions 2.5.3 and earlier where a user in one namespace can revoke or renew leases belonging to another namespace. This is achieved by exploiting the legacy, undocumented `sys/revoke` and `sys/renew` endpoints. An attacker with knowledge of a valid lease ID from a different namespace can leverage these endpoints to disrupt service or potentially gain unauthorized access to secrets. This vulnerability, identified as CVE-2026-45808, allows bypassing of intended ACL restrictions. The issue is resolved in OpenBao v2.5.4.

## Attack Chain

1.  Attacker gains access to a valid lease ID from a target namespace, either through unintentional leakage or through malicious insider activity.
2.  Attacker crafts an HTTP request targeting the legacy `sys/revoke` endpoint, including the stolen lease ID in the request body.
3.  The OpenBao server processes the request to the `sys/revoke` endpoint.
4.  Due to the legacy nature of the endpoint, ACL checks are bypassed.
5.  The targeted lease is revoked, rendering any associated credentials invalid.
6.  If the attacker targets the `sys/renew` endpoint, the lease will be renewed with settings controlled by the attacker.
7.  The affected application or service relying on the revoked lease experiences a denial of service or disruption.
8.  Depending on the targeted secrets, an attacker might gain unauthorized access to the target application or service if they were able to successfully renew the lease.

## Impact

Successful exploitation of CVE-2026-45808 can lead to denial of service for applications relying on OpenBao-managed secrets. In multi-tenant environments, this can impact services in other namespaces, even without proper authorization. While there is no direct information disclosure, unauthorized lease revocation and renewal can interrupt legitimate operations. The severity is high because it impacts availability of critical services.

## Recommendation

*   Upgrade OpenBao to version 2.5.4 or later to patch CVE-2026-45808.
*   Monitor OpenBao logs for requests to the `/sys/revoke` endpoint, which may indicate unauthorized lease revocation attempts (see Sigma rule below).
*   Implement strict lease ID handling procedures within your organization to prevent unintended leakage.
*   Consider disabling or restricting access to the `sys/revoke` and `sys/renew` endpoints through appropriate ACL policies as a temporary mitigation measure until the upgrade is complete.
