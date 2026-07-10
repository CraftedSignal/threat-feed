---
title: Paperclip Unauthenticated Remote Code Execution via Import Authorization Bypass
slug: 2024-01-09-paperclip-rce
description: An unauthenticated attacker can achieve remote code execution on Paperclip instances by exploiting multiple vulnerabilities, including open signup, self-approval of CLI authentication challenges, and missing authorization checks in the company import endpoint, leading to arbitrary command execution as the server's OS user.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - paperclip
  - rce
  - authentication-bypass
  - code-execution
vendors:
  - Paperclip
products:
  - Paperclip
  - paperclipai
  - '@paperclipai/server'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://github.com/advisories/GHSA-68qg-g8mg-6pr7
iocs:
  - type: email
    value: attacker@evil.com
ioc_counts:
  email: 1
rules:
  - title: Detect Company Import Without Instance Admin
    description: Detects attempts to import a new company without instance administrator privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect CLI Auth Challenge Creation
    description: Detects the creation of CLI auth challenges, which may be followed by unauthorized approval.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Paperclip is vulnerable to an unauthenticated remote code execution (RCE) flaw, affecting instances running in `authenticated` mode with default configurations. This vulnerability allows attackers to gain full control of the system without requiring any user interaction or credentials. The exploit chain consists of several steps, including creating an account without email verification, generating and approving a CLI authentication token, and exploiting a missing authorization check in the company import endpoint. This allows the attacker to deploy a malicious agent configured with a process adapter, enabling arbitrary command execution as the server's OS user. The vulnerability affects versions prior to 2026.410.0 of the `paperclipai` and `@paperclipai/server` npm packages.

## Attack Chain

1. **Account Creation:** The attacker creates a new account via the `/api/auth/sign-up/email` endpoint. No invite token or email verification is required.
2. **Sign In:** The attacker signs in with the newly created account via the `/api/auth/sign-in/email` endpoint, obtaining a session cookie.
3. **CLI Auth Challenge Creation:** The attacker creates a CLI auth challenge via the `/api/cli-auth/challenges` endpoint. No authentication is needed for this step. The response includes a `token` and `boardApiToken`.
4. **CLI Auth Challenge Approval:** The attacker approves the CLI auth challenge via the `/api/cli-auth/challenges/<id>/approve` endpoint using the session cookie obtained in step 2. The server only verifies that the caller is a board user, not that they are the challenge creator.
5. **Company Import:** The attacker exploits the missing `assertInstanceAdmin` check in the `/api/companies/import` endpoint to import a malicious company configuration. This configuration includes an agent with a `process` adapter that specifies a command to execute.
6. **Agent Trigger:** The attacker triggers the malicious agent via the `/api/agents/<agent-id>/wakeup` endpoint.
7. **Command Execution:** The `process` adapter executes the attacker-specified command (e.g., `bash -c "id > /tmp/pwned.txt && ..."`), resulting in code execution as the server's OS user.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary commands as the Paperclip server's OS user. This grants:

- Full filesystem access (read/write as the server user)
- Access to all data in the Paperclip database
- Ability to pivot to internal network services
- Ability to disrupt all agent operations

The attack is fully automated and works against the default deployment configuration, posing a critical risk to affected systems.

## Recommendation

- **Disable open registration by default:** Modify `server/src/config.ts:172` to change `?? false` to `?? true` and document `PAPERCLIP_AUTH_DISABLE_SIGN_UP` in the deployment guide.
- **Prevent CLI auth self-approval:**  Modify `server/src/routes/access.ts` around line 1700 to reject when the approving user is the same user who created the challenge.
- **Require email verification:** Modify `server/src/auth/better-auth.ts:91` to set `requireEmailVerification: true`.
- **Add `assertInstanceAdmin` to the import endpoint for `new_company` mode:** Modify `server/src/routes/companies.ts`, lines 161-176, to include the `assertInstanceAdmin` check for `POST /import` and `POST /import/preview` when `mode` is set to `new_company`.
- **Monitor web server logs** for POST requests to `/api/companies/import` that do not originate from an instance administrator to detect potential exploitation attempts, utilizing the rule below.
