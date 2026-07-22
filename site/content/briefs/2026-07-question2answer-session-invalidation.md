---
title: Question2Answer Session Invalidation Vulnerability
slug: 2026-07-question2answer-session-invalidation
description: Attackers can exploit CVE-2026-64829, a session invalidation vulnerability in Question2Answer through version 1.8.8, where the forgot-password reset flow fails to clear the sessioncode field, allowing an attacker with a previously obtained remember-me cookie to retain authenticated access even after the account's password has been reset.
date: "2026-07-22T20:19:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - question2answer
  - vulnerability
  - session-management
  - web-application
  - cve
vendors:
  - Question2Answer
products:
  - Question2Answer <= 1.8.8
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Web Session Cookie
    evidence: allows attackers with a previously obtained remember-me cookie to retain authenticated access by exploiting the forgot-password reset flow's failure to clear the sessioncode field
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows attackers... to retain authenticated access... by continuing to use the old, persistent cookie
    confidence_band: high
cves:
  - id: CVE-2026-64829
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64829
---

CVE-2026-64829 details a critical session invalidation vulnerability present in Question2Answer versions up to and including 1.8.8. This flaw arises because the application's `forgot-password` reset flow, handled by `qa_finish_reset_user()` in `qa-include/app/users-edit.php`, fails to clear the `sessioncode` field within existing `qa_session` cookies. Unlike the standard password-change mechanism in `qa-include/pages/account.php`, which properly invalidates persistent sessions, the reset flow neglects this crucial step. Consequently, any attacker who has previously acquired a legitimate `remember-me` cookie for a target account can continue to maintain authenticated access to that account even after the rightful owner successfully performs a password reset. This bypass of intended security measures allows for persistent unauthorized access, posing a significant risk to user data and application integrity.

## Attack Chain

1. **Initial Access**: An attacker obtains a legitimate `remember-me` cookie associated with a target user's Question2Answer account through unspecified means (e.g., prior credential compromise, client-side vulnerability, or direct access to the victim's browser).
2. **Authenticated Session Establishment**: The attacker utilizes the acquired `remember-me` cookie to successfully authenticate and establish an active session with the vulnerable Question2Answer application.
3. **Legitimate User Initiates Reset**: The legitimate account owner initiates a password reset for their account through the `forgot-password` functionality provided by Question2Answer.
4. **Password Reset Completion**: The legitimate user completes the password reset process, thereby changing their account password.
5. **Flawed Session Invalidation**: During the password reset, the `qa_finish_reset_user()` function in `qa-include/app/users-edit.php` updates the user's password but fails to invalidate or clear the `sessioncode` associated with the previously issued `qa_session` (remember-me) cookie.
6. **Persistent Cookie Usage**: The attacker, still possessing the original `remember-me` cookie with its uncleared `sessioncode`, continues to send requests to the Question2Answer application using this cookie.
7. **Unauthorized Access Maintenance**: The Question2Answer application validates the persistent `remember-me` cookie as still valid, granting the attacker continued authenticated access to the user's account, effectively bypassing the intended security measure of a password change.
8. **Impact**: The attacker maintains unauthorized persistent access to the user's account, enabling them to perform actions, view private information, or manipulate content as the legitimate user.

## Impact

Successful exploitation of CVE-2026-64829 results in a persistent breach of account confidentiality and integrity. An attacker can maintain full authenticated access to a user's Question2Answer account indefinitely, even after the legitimate user has changed their password. This allows the attacker to perform any action the user could, such as accessing sensitive user profiles, posting malicious content, defacing sections of the platform, sending messages under the user's identity, or extracting private data. While specific victim counts are not available, all Question2Answer installations running versions through 1.8.8 are susceptible, potentially exposing personal information and compromising the platform's reputation and trust for its entire user base.

## Recommendation

* Apply the patch for CVE-2026-64829 from Question2Answer when it becomes available to remediate the session invalidation vulnerability.
* Monitor web server access logs for `qa-include/app/users-edit.php` for unusual activity, particularly focusing on requests immediately following a user-initiated password reset.
* Implement application-level logging to correlate password reset events with subsequent authenticated sessions, looking for `qa_session` cookies that remain active after a reset.
* Consider implementing a feature to allow users or administrators to forcefully invalidate all active sessions for an account, especially after a suspected compromise or password reset.
