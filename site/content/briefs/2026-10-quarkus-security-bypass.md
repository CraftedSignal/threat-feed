---
title: Security Control Bypass in Quarkus REST Data Panache via @MethodProperties
slug: 2026-10-quarkus-security-bypass
description: A code generation flaw in Quarkus REST Data Panache allows unauthenticated attackers to bypass class-level security requirements when using @MethodProperties without explicit role re-declaration.
date: "2026-10-12T22:37:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:redhat:quarkus:*:*:*:*:*:*:*:*
tags:
  - web-application-security
  - configuration-flaw
  - cve-2026-87744
vendors:
  - Red Hat
products:
  - Quarkus REST Data Panache
cves:
  - id: CVE-2026-87744
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87744
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Review codebase for unauthorized use of @MethodProperties in REST Data Panache
      owner: Application Security
      due: 48h
      evidence: Source documentation of @MethodProperties misconfiguration
  mitigation_plan:
    - priority: immediate
      action: Manually re-apply @RolesAllowed to all endpoints customized with @MethodProperties
      owner: Application Security
      addresses: CVE-2026-87744
      evidence: Mitigation path identified in overview
---

CVE-2026-87744 describes a security vulnerability within the Quarkus REST Data Panache extension. The flaw originates in the code generation process during the application build phase. When a developer utilizes the @MethodProperties annotation to customize a specific REST operation, the generator fails to carry over existing class-level security constraints to the generated endpoint. Unless a developer explicitly re-declares security roles for the customized operation, the generator silently defaults the endpoint to permissive, unauthenticated access. This misconfiguration exposes sensitive application interfaces to any remote, unauthenticated user, facilitating potential unauthorized information disclosure or arbitrary data modification depending on the functionality of the exposed resource. The vulnerability impacts applications relying on Quarkus REST Data Panache for automated endpoint exposure.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.1, representing a high risk of unauthorized access to sensitive application data. Exploitation is possible by any remote unauthenticated attacker who identifies affected endpoints that were improperly customized. Successful exploitation allows for unauthorized data access or modification, potentially impacting the confidentiality and integrity of backend data stores.

## Recommendation

* Conduct an audit of all Quarkus projects utilizing the REST Data Panache extension to identify endpoints where @MethodProperties is in use.
* Verify that any operation customized with @MethodProperties explicitly includes security annotations (such as @RolesAllowed) to re-enforce access controls.
* Update Quarkus REST Data Panache to the version containing the fix once released by the vendor, and rebuild the application to ensure the code generator correctly applies security policies.
