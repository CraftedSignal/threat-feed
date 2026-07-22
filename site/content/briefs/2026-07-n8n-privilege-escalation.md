---
title: n8n Privilege Escalation and Code Execution via Flawed JWT Scope Assignment (CVE-2026-65595)
slug: 2026-07-n8n-privilege-escalation
description: A critical vulnerability, CVE-2026-65595, in n8n's Token Exchange module allows low-privileged users to achieve privilege escalation and potential code execution by exploiting incorrect Public API key scope assignments to JWTs, enabling administrative operations.
date: "2026-07-22T22:02:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - code-execution
  - vulnerability
  - jwt-exploitation
vendors:
  - n8n GmbH
products:
  - n8n >= 2.30.0, < 2.30.1
  - n8n < 2.29.8
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: JWTs issued through the Token Exchange module were assigned all Public API key scopes, regardless of the acting user's actual role. A low-privileged user who could obtain a valid external JWT trusted by a configured issuer could therefore use the resulting access token to invoke administrator-only Public API operations, such as role escalation, user creation, and user deletion.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Community Package installation additionally requires `N8N_COMMUNITY_PACKAGES_ENABLED=true` and `N8N_UNVERIFIED_PACKAGES_ENABLED=true`... to eliminate the code execution path.
    confidence_band: high
cves:
  - id: CVE-2026-65595
references:
  - https://github.com/advisories/GHSA-777w-rpr6-c52h
---

A high-severity vulnerability, identified as CVE-2026-65595, has been discovered in n8n versions prior to 2.30.1 and 2.29.8. This flaw resides within the Token Exchange module, where JSON Web Tokens (JWTs) issued via this mechanism are erroneously assigned all Public API key scopes, irrespective of the authenticating user's actual permissions. This critical misconfiguration allows a low-privileged attacker, who successfully obtains a valid external JWT trusted by a configured issuer, to exchange it for an overly permissive n8n access token. With this escalated token, the attacker can then invoke administrator-only Public API operations, potentially leading to full privilege escalation within the n8n instance and even arbitrary code execution if the Community Packages feature is enabled. The issue impacts n8n instances with both Token Exchange (`N8N_TOKEN_EXCHANGE_ENABLED=true`) and the Public API enabled.

## Attack Chain

1. An attacker, initially possessing low privileges, obtains a valid external JWT that is trusted by a configured issuer within the target n8n instance.
2. The attacker sends a request to the n8n instance's Token Exchange module, presenting the valid external JWT for exchange.
3. The n8n system processes the token exchange, and due to CVE-2026-65595, mistakenly assigns all available Public API key scopes to the newly issued internal access token.
4. The attacker receives the over-privileged internal JWT, which now grants them full administrative access to the Public API, bypassing their original low-privileged role.
5. Using this compromised token, the attacker performs administrator-only Public API operations, such as escalating roles for existing users, creating new administrative user accounts, or deleting users.
6. If n8n's Community Packages feature is enabled (`N8N_COMMUNITY_PACKAGES_ENABLED=true` and `N8N_UNVERIFIED_PACKAGES_ENABLED=true`), the attacker can leverage their administrative privileges.
7. The attacker installs and executes unverified or malicious packages through the Public API.
8. This leads to arbitrary code execution on the underlying server hosting the n8n instance, achieving full system compromise.

## Impact

The vulnerability allows a low-privileged user to achieve full privilege escalation within an affected n8n instance, gaining administrative control. If successful, an attacker can perform actions typically reserved for administrators, including altering user roles, creating new administrative accounts, or deleting existing users. In scenarios where the instance also has the Community Packages feature enabled, this can further lead to remote code execution, granting the attacker arbitrary control over the host system. While the number of specific victims is not public, any organization using affected n8n versions with the Token Exchange and Public API features enabled is at risk. Role escalation impact is greater for instances with an Advanced Permissions license.

## Recommendation

* **Patch CVE-2026-65595 immediately:** Upgrade all n8n instances to version 2.30.1, 2.29.8, or later to remediate the vulnerability.
* **Disable Token Exchange as a workaround:** If immediate patching is not possible, disable the Token Exchange feature by setting `N8N_TOKEN_EXCHANGE_ENABLED=false` or `N8N_ENV_FEAT_TOKEN_EXCHANGE=false` in your n8n environment configuration.
* **Restrict Public API access:** As a temporary mitigation, restrict Public API access at the network level to only trusted clients.
* **Disable unverified Community Package installation:** To eliminate the code execution path, set `N8N_UNVERIFIED_PACKAGES_ENABLED=false` in your n8n environment configuration.
