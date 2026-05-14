---
title: Portainer Kubernetes Authorization Bypass Vulnerability (CVE-2026-44882)
slug: 2026-05-portainer-auth-bypass
description: Portainer versions 2.33.0 through 2.33.7 are vulnerable to an authorization bypass in the `kubeClientMiddleware` component, allowing users with valid Portainer sessions to bypass Kubernetes authorization checks and access Kubernetes API endpoints on environments that their role should not permit (CVE-2026-44882).
date: "2026-05-14T16:29:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - kubernetes
  - privilege-escalation
vendors:
  - Portainer
products:
  - Portainer (>= 2.33.0, < 2.33.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-mgq6-4x29-88r3
  - CVE-2026-44882
rules:
  - title: Detect Portainer Kubernetes Authorization Bypass Attempt
    description: Detects CVE-2026-44882 exploitation — Monitors for 403 Forbidden errors followed by Kubernetes API requests indicative of a potential authorization bypass attempt in Portainer
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Portainer Unauthorized Kubernetes Access via API
    description: Detects potential exploitation of CVE-2026-44882 where Kubernetes API requests are made without a preceding authentication event in Portainer logs, indicating a possible bypass of authorization.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Portainer, a web UI for managing container environments, contains an authorization bypass vulnerability (CVE-2026-44882) within its Kubernetes proxy functionality. The vulnerability exists in the `kubeClientMiddleware` component responsible for validating user tokens before proxying requests to Kubernetes clusters. Due to a missing `return` statement after an error check, the middleware fails to properly terminate execution, leading to a nil `tokenData` value being passed to subsequent authorization checks, effectively bypassing them. This allows a low-privileged Portainer user to access Kubernetes API endpoints without proper authorization. The vulnerability affects Portainer versions 2.33.0 through 2.33.7.

## Attack Chain

1. An attacker authenticates to Portainer with a valid, low-privileged user account.
2. The attacker attempts to access a Kubernetes API endpoint within a managed cluster through the Portainer UI.
3. Portainer's `AuthenticatedAccess` bouncer validates the initial Portainer session, allowing the request to proceed.
4. The request reaches the `kubeClientMiddleware` in `api/http/handler/kubernetes/handler.go`.
5. `security.RetrieveTokenData` fails, because the user lacks specific permissions for the target Kubernetes endpoint.
6. The middleware writes an HTTP 403 error to the response stream but fails to terminate execution due to a missing `return` statement.
7. Execution continues with a nil `tokenData` value, bypassing the intended authorization check.
8. The request is forwarded to the Kubernetes API server using Portainer's service account credentials, potentially allowing unauthorized access and modification of cluster resources, depending on the permissions granted to Portainer's service account.

## Impact

Successful exploitation of this vulnerability allows a low-privileged Portainer user to bypass Kubernetes authorization checks and access Kubernetes API endpoints that they should not have access to. The impact includes the ability to read and modify namespaced Kubernetes resources such as pods, secrets, config maps, and deployments. Depending on the service account permissions, this could lead to lateral movement within the cluster if exposed secrets contain credentials for other services or infrastructure components.

## Recommendation

*   Upgrade to Portainer version 2.33.8 or later to remediate the vulnerability (CVE-2026-44882).
*   Restrict Kubernetes endpoint access within Portainer to only those users who require it, as described in the "Workarounds" section of the advisory.
*   Ensure the service account used by Portainer to proxy cluster requests follows the principle of least privilege, limiting the potential impact of a successful authorization bypass, as described in the advisory.
*   Deploy the Sigma rule "Detect Portainer Kubernetes Authorization Bypass Attempt" to detect attempts to exploit this vulnerability by monitoring for 403 errors followed by Kubernetes API requests.
