---
title: 'CVE-2026-59713: Leantime OIDC Login CSRF leading to Session Fixation'
slug: 2026-07-leantime-oidc-csrf
description: CVE-2026-59713 identifies a high-severity OIDC login Cross-Site Request Forgery (CSRF) vulnerability in Leantime's verifyState() method, allowing attackers to craft malicious callback URLs with attacker-controlled authorization codes to perform session fixation and log victims into an attacker's session.
date: "2026-07-06T21:23:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csrf
  - oidc
  - session-fixation
  - web-application
  - vulnerability
  - leantime
vendors:
  - Leantime
products:
  - Leantime
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Leantime contains an OIDC login CSRF vulnerability in the verifyState() method that unconditionally returns true without validating state parameters.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can craft malicious callback URLs... By tricking a victim into clicking this URL...
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: logging victims in as the attacker.
    confidence_band: high
cves:
  - id: CVE-2026-59713
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59713
---

A significant security vulnerability, CVE-2026-59713, has been disclosed in Leantime, an open-source project management system. This high-severity flaw (CVSS v3.1 Base Score: 8.1) exists within the OpenID Connect (OIDC) login mechanism, specifically in the `verifyState()` method. The method is designed to validate state parameters to prevent Cross-Site Request Forgery (CSRF) attacks but unconditionally returns `true`, effectively bypassing this crucial security check. Attackers can exploit this by pre-authenticating to Leantime via OIDC and then crafting a malicious callback URL containing their own valid authorization code. By tricking a victim into clicking this URL, the victim is inadvertently logged into the attacker's Leantime session, leading to session fixation. This can enable the attacker to manipulate the victim's perception and actions within the application, potentially leading to unauthorized data exposure or malicious activity conducted under the guise of the victim's interaction.

## Attack Chain

1. An attacker first registers an account and authenticates to Leantime through their configured OIDC provider.
2. The attacker then captures the session identifier or authorization code generated during their legitimate OIDC authentication flow.
3. The attacker crafts a malicious URL for the Leantime application's OIDC callback endpoint, embedding the captured attacker-controlled authorization code.
4. The attacker delivers this crafted malicious URL to a target victim, typically via social engineering methods such as a phishing email or message.
5. The victim is enticed to click the malicious link, which directs their browser to the vulnerable Leantime OIDC callback endpoint.
6. Due to the flaw in the `verifyState()` method, Leantime processes the attacker's authorization code without validating the OIDC `state` parameter against the user's session.
7. The Leantime application then logs the victim's browser session into the attacker's pre-established account, effectively performing session fixation.
8. The victim, believing they are logged into their own account, may perform actions that are actually attributed to the attacker's account, potentially compromising data or application integrity.

## Impact

Successful exploitation of CVE-2026-59713 results in session fixation, where a victim is logged into an attacker's Leantime account without their explicit knowledge. While this does not directly grant the attacker access to the victim's *personal* Leantime account, it allows the attacker to trick the victim into performing actions within the application *as the attacker*. This poses a significant risk to data integrity and user trust. For instance, a victim might inadvertently modify or delete project data, publish sensitive information, or interact with other users, all under the attacker's identity. This can lead to confusion, data corruption, and potentially reputational damage for organizations using Leantime, as well as enabling sophisticated social engineering attacks where the victim is coerced into performing actions that benefit the attacker.

## Recommendation

*   **Patch CVE-2026-59713** on all Leantime instances immediately, as detailed by the vendor to address the `verifyState()` vulnerability.
*   Educate users on the risks of phishing and urge caution when clicking on suspicious links, especially those asking for login or appearing to redirect after authentication.
