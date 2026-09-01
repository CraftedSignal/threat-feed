---
title: Authentication Bypass in Support Genix WordPress Plugin
slug: 2026-09-support-genix-auth-bypass
description: The Support Genix WordPress plugin is vulnerable to authentication bypass and administrator account takeover due to a weak cryptographic implementation in the guest ticket login feature.
date: "2026-09-01T07:03:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:support_genix:helpdesk_ai_chatbot_knowledge_base_customer_support_ticketing_system:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - authentication-bypass
  - web-application-attack
vendors:
  - Support Genix
products:
  - Support Genix – Helpdesk, AI Chatbot, Knowledge Base & Customer Support Ticketing System (<= 1.4.52)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is due to... no capability check, nonce, or session validation on the publicly reachable /sgnix/?p=<token> endpoint.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This makes it possible for authenticated attackers... to exhaust the ~729,000-candidate keyspace entirely offline, recover the site-wide encryption key.
    confidence_band: high
cves:
  - id: CVE-2026-19806
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19806
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Support Genix plugin to version > 1.4.52
      owner: IT Operations
      due: 24h
      evidence: Source indicates the vulnerability exists in versions up to and including 1.4.52.
  mitigation_plan:
    - priority: immediate
      action: Block access to /sgnix/ endpoint via WAF
      owner: IT Operations
      addresses: CVE-2026-19806
      evidence: The endpoint /sgnix/ is the primary vector for authentication bypass.
---

The Support Genix plugin for WordPress (all versions up to and including 1.4.52) contains a critical cryptographic weakness in its `guest_ticket_login()` function. The plugin derives its site-wide AES-256-CBC encryption key using low-entropy inputs, specifically three two-digit random integers and a Unix timestamp hashed with `md5()`. This results in approximately 19.5 bits of entropy, which allows an attacker with subscriber-level access to exhaust the 729,000-candidate keyspace offline. 

The vulnerability is exposed via the publicly accessible `/sgnix/?p=<token>` endpoint, which lacks nonces, capability checks, or session validation. By obtaining a single legitimate guest ticket token, an attacker can perform a known-plaintext attack to recover the site-wide encryption key. Once the key is recovered, the attacker can forge a ticket token for any administrator-owned ticket. Submitting this forged token to the endpoint triggers `wp_set_auth_cookie()` for the target administrator, granting the attacker full administrative access to the site.

## Attack Chain

1. Attacker obtains a legitimate guest ticket token to serve as a known-plaintext oracle.
2. Attacker retrieves site metadata to estimate the plugin activation timestamp.
3. Attacker uses the known-plaintext and estimated timestamp to perform an offline brute-force attack on the 729,000-candidate keyspace.
4. Attacker successfully recovers the site-wide AES-256-CBC encryption key.
5. Attacker crafts a forged ticket token referencing a target administrator user ID and ticket ID.
6. Attacker sends an HTTP GET request to the `/sgnix/?p=` endpoint with the forged token as the parameter.
7. The plugin fails to validate the token's origin or authenticity and invokes `wp_set_auth_cookie()` for the administrator.
8. The WordPress site grants the attacker administrative privileges, completing the account takeover.

## Impact

Successful exploitation allows unauthenticated or low-privileged attackers to gain full administrative access to WordPress sites running the vulnerable plugin. This enables complete site takeover, including the ability to exfiltrate data, modify content, install malicious themes or plugins, and establish persistence, affecting any organization relying on the Support Genix plugin for helpdesk operations.

## Recommendation

Update the Support Genix WordPress plugin to a version released after 1.4.52 to remediate the cryptographic flaw. Until patching is possible, restrict access to the `/sgnix/` endpoint via web application firewall (WAF) rules or server-side configuration to prevent unauthenticated access. Monitor web server access logs for anomalous GET requests to `/sgnix/` that contain unusually long or repetitive `p` parameter values.
