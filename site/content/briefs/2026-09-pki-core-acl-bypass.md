---
title: Authorization Bypass in pki-core REST ACL Filter
slug: 2026-09-pki-core-acl-bypass
description: An ACL resolution flaw in pki-core allows unauthorized privilege escalation within the CA profile-management REST API by incorrectly prioritizing wildcard permissions over specific literal permissions.
date: "2026-09-21T18:29:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-80110
    cvss: 8.1
---

A vulnerability (CVE-2026-80110) exists within the pki-core v2 REST ACL filter, impacting how permission collisions are resolved between literal and wildcard keys. The filter performs lexicographic string comparison to select a tie-breaking permission rather than evaluating rule specificity. This design error causes wildcard-mapped permissions to erroneously supersede more specific literal-mapped permissions when both match a given request. 

In the context of the CA's profile-management REST API, this vulnerability allows a low-privileged user, such as a member of the Certificate Manager Agents group, to perform actions requiring higher-level privileges. Specifically, a request to 'POST /v2/profiles/raw' - which is intended to be restricted to users with 'profiles.create' permission - can be successfully authorized if the attacker possesses the 'profiles.approve' permission. This flaw directly undermines the security model of the Certificate Authority, potentially leading to unauthorized modifications of issuance policies and compromise of certificate integrity.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to bypass intended access control restrictions on sensitive administrative endpoints. In an enterprise environment, this leads to the unauthorized creation or modification of certificate profiles, which could be leveraged to subvert the certificate authority's issuance policy, perform fraudulent certificate issuance, or compromise the overall integrity
