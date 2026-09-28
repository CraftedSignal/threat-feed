---
title: Weak Authentication Vulnerability in LiteLLM (CVE-2026-93355)
slug: 2026-09-litellm-auth-bypass
description: LiteLLM contains a critical authentication flaw where failure to validate JWT email claims allows attackers to impersonate arbitrary users and escalate to administrative privileges.
date: "2026-09-28T22:22:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
vendors:
  - LiteLLM
products:
  - LiteLLM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: LiteLLM contains a weak authentication vulnerability that allows an attacker holding a valid JWT from the configured identity provider to authenticate as any existing user.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Attacker can... permanently overwrite the victim's stored identity binding to retain persistent unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-93355
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93355
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch LiteLLM to address CVE-2026-93355
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93355 vulnerability requires immediate remediation via vendor update.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to authentication endpoints via WAF or reverse proxy
      owner: IT Operations
      addresses: CVE-2026-93355
      evidence: Vulnerability allows unauthorized JWT authentication.
---

LiteLLM is susceptible to a weak authentication vulnerability, identified as CVE-2026-93355. The flaw exists within the application's JWT-based authentication flow, specifically regarding the handling of identity provider (IdP) tokens. When a user presents a JWT, the application performs an email-based lookup to identify the account. Crucially, the system fails to verify the 'email_verified' claim contained within the token. 

This oversight allows an attacker who possesses a valid JWT from a configured IdP to specify an unverified email address that corresponds to an existing target account. The application incorrectly maps the attacker's token to the victim's profile, granting the attacker the permissions associated with that account. In scenarios where the targeted account holds administrative roles, such as 'proxy_admin', the attacker can achieve full privilege escalation. Furthermore, the vulnerability enables the attacker to overwrite the stored identity binding for the victim, facilitating persistent unauthorized access to administrative interfaces, API key repositories, and user management functions. This impact is significant for organizations relying on LiteLLM for LLM orchestration and proxy services.

## Attack Chain

1. Attacker obtains a valid JWT from a configured IdP (e.g., via personal registration or unauthorized account creation).
2. Attacker modifies the JWT payload (if necessary) or uses an IdP account to inject an email address matching a victim's administrative account.
3. Attacker initiates an authentication request to the LiteLLM application passing the crafted JWT.
4. The LiteLLM authentication service processes the incoming JWT.
5. The service executes an email-based lookup for the account associated with the provided email string.
6. The service fails to validate the 'email_verified' claim, allowing the mapping to succeed despite the email being unverified.
7. LiteLLM establishes a session context for the victim user, granting the attacker administrative access (proxy_admin).
8. Attacker modifies identity bindings to permanently associate the victim's account with the attacker's controlled token, ensuring persistence.

## Impact

Successful exploitation of CVE-2026-93355 allows for full account takeover of any existing user within the LiteLLM instance. This includes accounts with administrative privileges, granting unauthorized access to sensitive API keys, proxy management, and infrastructure configurations. Given the centralized role of LiteLLM in proxying LLM interactions, this vulnerability poses a severe risk to the confidentiality and integrity of AI-driven workflows and associated data.

## Recommendation

Prioritize the immediate application of security patches or updates provided by the LiteLLM vendor to address CVE-2026-93355. Ensure that the application is configured to strictly enforce the 'email_verified' claim during JWT validation processes. If patching is not immediately feasible, restrict access to the authentication interface by implementing IP-based allowlisting at the reverse proxy or firewall layer to mitigate unauthenticated or unauthorized token injection attempts.
