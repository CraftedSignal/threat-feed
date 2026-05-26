---
title: FUXA Unauthenticated Remote Code Execution via Script Test Mode Authorization Bypass (CVE-2026-43947)
slug: 2026-05-fuxa-rce
description: FUXA version 1.3.0 is vulnerable to unauthenticated remote code execution (CVE-2026-43947) because the /api/runscript endpoint, when in test mode, executes attacker-supplied code without proper authorization, allowing execution of arbitrary commands if a server-side script exists with permissive permissions.
date: "2026-05-26T23:48:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - unauthenticated
  - cve-2026-43947
vendors:
  - npm
products:
  - fuxa-server (1.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: CommandLine Interface
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-rg3m-cfq7-g6h6
  - CVE-2026-43947
rules:
  - title: Detect FUXA Unauthenticated RCE Attempt via Script Test Mode (CVE-2026-43947)
    description: Detects CVE-2026-43947 exploitation — Attempts to execute arbitrary code on a FUXA server via the /api/runscript endpoint with test mode enabled without authentication.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - webserver
  - title: Detect FUXA Project Info Disclosure Attempt
    description: Detects attempts to retrieve FUXA project information without authentication, which could precede CVE-2026-43947 exploitation.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

FUXA version 1.3.0 contains an unauthenticated remote code execution vulnerability (CVE-2026-43947) that can be exploited if the `secureEnabled` setting is set to `true`. The vulnerability lies in the `/api/runscript` endpoint, where, under test mode (`test: true`), the application bypasses the intended authorization checks for stored scripts and directly executes attacker-supplied code. This allows unauthenticated attackers knowing a valid script ID and name to execute arbitrary code, provided that at least one server-side script exists within the project and is accessible without restrictive permissions. This flaw allows a threat actor to gain remote code execution capabilities on the FUXA server, potentially leading to further compromise.

## Attack Chain

1. The attacker sends a `GET` request to `/api/project` to retrieve script IDs and names. This endpoint does not require authentication.
2. The server responds with a JSON payload containing a list of scripts, including their IDs, names, and permissions.
3. The attacker identifies a script ID and name with permissive permissions or no permissions set. This is required for the authorization bypass to succeed.
4. The attacker crafts a `POST` request to `/api/runscript`, setting the `test` parameter to `true` and including malicious code in the `code` parameter. The script ID and name from the previous step are also included in the request.
5. The server's `verifyToken` middleware automatically generates a valid guest JWT if no token is provided in the request, effectively authenticating the attacker as a guest user.
6. The `isAuthorised` function retrieves the stored script by ID and validates the stored script's permissions. If the script has no permission field set (or `permission: 0`), the check passes for any user, including guests.
7. The `runTestScript` function takes the attacker's `code` from the request body and compiles it into a Node.js module using `Module._compile`.
8. The compiled code is then executed with full access to `require`, `child_process`, `fs`, and the entire Node.js runtime, resulting in remote code execution.

## Impact

Successful exploitation allows any network-reachable attacker to achieve Remote Code Execution on the FUXA server without authentication. The attacker can execute arbitrary commands on the host, potentially accessing configured device connections, credentials, and compromising industrial control functionality managed by the FUXA instance. This vulnerability requires the presence of an existing server-side script with permissive permissions configured, but it can have severe implications for the security and integrity of affected systems.

## Recommendation

*   Deploy the Sigma rule titled "Detect FUXA Unauthenticated RCE Attempt via Script Test Mode (CVE-2026-43947)" to your SIEM to identify exploitation attempts targeting the `/api/runscript` endpoint.
*   Apply access controls to the `/api/runscript` endpoint and require authentication for all script execution requests.
*   Monitor web server logs for unusual POST requests to `/api/runscript` containing the parameter `test: true`.
*   Inspect running FUXA instances to determine if the fuxa-server package version is 1.3.0.
