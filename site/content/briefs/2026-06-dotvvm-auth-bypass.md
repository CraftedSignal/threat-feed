---
title: DotVVM AuthorizeActionFilter Critical Authorization Bypass
slug: 2026-06-dotvvm-auth-bypass
description: A critical authorization bypass vulnerability exists in the `AuthorizeActionFilter` class within the DotVVM framework, failing to perform any authorization checks and allowing attackers to bypass intended access restrictions without specific exploitation techniques, impacting all users relying on `AuthorizeActionFilter` for security. Patched versions include DotVVM 4.3.15, 4.2.11, and 5.0.0-preview09; `AuthorizeAttribute` can be used as a workaround.
date: "2026-06-19T15:15:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization-bypass
  - web-application
  - vulnerability
  - dotvvm
vendors:
  - DotVVM
products:
  - DotVVM (< 4.2.11)
  - DotVVM (> 4.3.0-preview01-final, < 4.3.15)
  - DotVVM (>= 5.0.0-preview01-final, < 5.0.0-preview09-final)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/advisories/GHSA-c8qj-jx8j-fg2w
rules:
  - title: Detect Successful Access to Common Sensitive Web GET Paths
    description: Detects successful HTTP GET requests (200 OK) to URIs commonly associated with administrative panels or sensitive application functionalities. While generic, successful access to these paths by an unauthorized user could indicate an authorization bypass, such as GHSA-c8qj-jx8j-fg2w in DotVVM.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - privilege_escalation
    techniques:
      - T1005
      - T1068
    data_sources:
      - webserver
  - title: Detect Successful Access to Common Sensitive Web POST Paths
    description: Detects successful HTTP POST requests (200 OK) to URIs commonly associated with modifying or creating resources within administrative panels or sensitive application functionalities. While generic, successful POST access to these paths by an unauthorized user could indicate an authorization bypass, such as GHSA-c8qj-jx8j-fg2w in DotVVM.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
      - T1561
    data_sources:
      - webserver
rules_count: 2
---

A critical authorization bypass vulnerability (GHSA-c8qj-jx8j-fg2w) has been identified in the `AuthorizeActionFilter` class within the DotVVM framework. This flaw affects all users who have implemented the `AuthorizeActionFilter` to secure parts of their web applications. The component, intended to enforce access controls, is inherently flawed and performs no actual authorization checks, effectively allowing any request to bypass the filter and access protected resources. This vulnerability does not require complex 'hacking' techniques; an attacker simply needs to make a standard request to a supposedly protected endpoint, and the filter will mistakenly grant access. This flaw impacts DotVVM versions prior to 4.2.11, between 4.3.0-preview01-final and 4.3.15, and between 5.0.0-preview01-final and 5.0.0-preview09-final.

## Attack Chain

1.  **Attacker identifies target application:** An attacker identifies a web application that is developed using the DotVVM framework.
2.  **Vulnerability discovery:** The attacker becomes aware of the `AuthorizeActionFilter` authorization bypass vulnerability (GHSA-c8qj-jx8j-fg2w) in DotVVM, understanding its nature as a complete bypass.
3.  **Endpoint identification:** The attacker probes or researches the target application to identify specific web application endpoints or functionalities that are intended to be protected by the vulnerable `AuthorizeActionFilter` (e.g., `/admin`, `/dashboard`, `/api/users`).
4.  **Craft unauthorized request:** The attacker crafts a standard HTTP GET or POST request to one of these identified protected endpoints, intentionally omitting or providing insufficient authentication or authorization tokens.
5.  **Application processes request:** The vulnerable DotVVM application receives and processes the crafted HTTP request, routing it to the appropriate controller action.
6.  **Filter execution (no check):** The `AuthorizeActionFilter` component, despite being invoked for the protected endpoint, executes without performing any authorization validation due to its internal flaw, effectively doing nothing.
7.  **Unauthorized access granted:** The DotVVM application, mistakenly assuming authorization has occurred, proceeds to execute the action and grants the attacker full access to the intended protected resource or functionality.
8.  **Impact achieved:** The attacker successfully bypasses security controls, leading to unauthorized data exposure, privilege escalation, or the ability to perform restricted actions within the compromised application.

## Impact

All applications utilizing the `AuthorizeActionFilter` class within the specified vulnerable DotVVM versions are at critical risk. The complete failure of the filter to perform any authorization checks means that any resource or functionality intended to be protected by it is openly accessible to unauthorized individuals. This directly leads to unauthorized access to sensitive data, compromise of administrative functions, or complete takeover of application features that were meant to be restricted. The number of potentially affected applications is widespread among DotVVM users who relied on this specific authorization mechanism for security.

## Recommendation

*   **Patch immediately:** Upgrade all affected DotVVM installations to a patched version (DotVVM 4.3.15, 4.2.11, or 5.0.0-preview09) to remediate the GHSA-c8qj-jx8j-fg2w vulnerability.
*   **Implement workaround:** For immediate protection if patching is not feasible, replace all instances of `AuthorizeActionFilter` with `AuthorizeAttribute` in your DotVVM application code.
*   **Monitor webserver logs:** Deploy the Sigma rules "Detect Successful Access to Common Sensitive Web GET Paths" and "Detect Successful Access to Common Sensitive Web POST Paths" to monitor for HTTP 200 responses to known administrative or sensitive URIs, as this can indicate potential unauthorized access.
*   **Application-level logging:** Implement robust application-level logging for all sensitive actions and authorization events to identify successful access to resources that should require specific permissions.
