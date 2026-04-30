---
title: Paperclip Unauthenticated API Access Vulnerability
slug: 2026-04-paperclip-auth-bypass
description: Paperclip application suffers from multiple unauthenticated API access vulnerabilities allowing attackers to access sensitive data, gather reconnaissance, and potentially bypass authentication.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - paperclip
  - authentication-bypass
  - api-vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-xfqj-r5qw-8g4j
rules:
  - title: Detect Paperclip Unauthenticated Health Endpoint Access
    description: Detects unauthenticated access to the /api/health endpoint, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Unauthenticated Skill Endpoint Access
    description: Detects unauthenticated access to the /api/skills/index endpoint, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Paperclip, a software application, contains multiple API endpoints that lack proper authentication checks, even when the application is configured in "authenticated" mode. This vulnerability allows unauthenticated access to sensitive information and functionality. Observed in versions prior to 2026.416.0, the issue impacts the confidentiality and integrity of the application. An attacker can exploit these vulnerabilities to gather reconnaissance information about the deployment, access heartbeat run issues, retrieve agent instructions, and potentially bypass authentication mechanisms via unauthenticated CLI challenge creation. The disclosed information includes API structure, authentication mechanisms, and internal workflows, which can be leveraged for further malicious activities.

## Attack Chain

1.  The attacker sends an unauthenticated GET request to `/api/health` to obtain deployment mode, exposure setting, auth status, version, and feature flags.
2.  The attacker sends an unauthenticated GET request to `/api/skills/index` to retrieve a list of available skill endpoints.
3.  The attacker sends an unauthenticated GET request to `/api/skills/paperclip` to leak the agent heartbeat procedure, API endpoints, parameters, authentication mechanisms, and agent coordination protocols.
4.  The attacker sends an unauthenticated GET request to `/api/heartbeat-runs/:runId/issues`, attempting to access issue data for a heartbeat run by guessing or obtaining a valid `runId`.
5.  The attacker sends an unauthenticated POST request to `/api/cli-auth/challenges` with a JSON payload containing a command to create a CLI authentication challenge and obtain a `boardApiToken`.
6.  The attacker uses the leaked information to map the internal API structure and plan further attacks or unauthorized access.
7.  The attacker exploits the `boardApiToken` obtained in step 5, combined with open registration (if enabled), to persistently generate API keys.

## Impact

This vulnerability results in significant data exposure, including heartbeat run issues, agent instructions, and internal API structure. An attacker can fingerprint the deployment and map the entire internal API for reconnaissance purposes. Successful exploitation of the unauthenticated CLI challenge creation allows for authentication bypass, potentially leading to a full remote code execution chain. The vulnerability affects organizations using Paperclip versions prior to 2026.416.0. A successful attack can compromise sensitive data, facilitate unauthorized access, and lead to further malicious activities.

## Recommendation

*   Apply the patch to upgrade Paperclip to version 2026.416.0 or later, which addresses the unauthenticated API access vulnerabilities.
*   Implement authentication checks for the `/api/heartbeat-runs/:runId/issues` endpoint in `server/src/routes/activity.ts` using `assertCompanyAccess`.
*   Implement authentication checks for the `/api/cli-auth/challenges` endpoint in `server/src/routes/access.ts` using `assertBoard`.
*   Implement authentication checks for the `/api/skills/index` and `/api/skills/:skillName` endpoints in `server/src/routes/access.ts`.
*   Reduce the information exposed by the `/api/health` endpoint by removing sensitive data such as `deploymentMode`, `deploymentExposure`, and `version` or by requiring authentication via `assertBoard`.
*   Deploy the Sigma rule "Detect Paperclip Unauthenticated Health Endpoint Access" to identify unauthorized access attempts to the `/api/health` endpoint.
