---
title: 'motionEye: Authentication possible via password hash'
slug: 2026-07-motioneye-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-46488) in motionEye allows unauthenticated attackers to impersonate any user, including administrators, by manipulating client-controlled cookies (`meye_password_hash` and `meye_username`), with the application trusting these cookies without server-side validation, leading to full account compromise, data enumeration, destruction, and exfiltration.
date: "2026-07-03T11:04:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - web-vulnerability
  - cve
  - motioneye
  - linux
vendors:
  - MotionEye
products:
  - motionEye (< 0.44.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: unauthenticated attacker can set or modify these cookies to impersonate another user
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: password-hash value and username for the admin account used by the application is stored in `/etc/motioneye/motion.conf` which is globally readable by default on the local system.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: application accepts the client-supplied cookies named `meye_password_hash` and `meye_username` as sufficient authentication material... impersonate arbitrary users without knowledge of the plaintext password.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Account Manipulation
    evidence: Attacker persistence by changing the password
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Enumeration of data
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Exfiltration of data
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Degradation
    evidence: Destruction of data
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r3cw-c95m-wfh9
iocs:
  - type: file_path
    value: /etc/motioneye/motion.conf
ioc_counts:
  file_path: 1
rules:
  - title: Detect motionEye Admin Credential File Access
    description: Detects attempts to read the motionEye admin credential file (/etc/motioneye/motion.conf), which contains the username and password hash and is globally readable by default on the local system. Access to this file's contents can be used to bypass authentication (CVE-2026-46488).
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A critical authentication bypass vulnerability (CVE-2026-46488) affects motionEye versions prior to 0.44.0, enabling unauthenticated attackers to impersonate arbitrary users, including administrators. This flaw stems from the application's improper trust in client-supplied cookies, specifically `meye_password_hash` and `meye_username`. Attackers can manually set or modify these cookies to establish an authenticated session without knowing the plaintext password, bypassing the intended login mechanism. The vulnerability is exacerbated by the fact that motionEye stores the admin username and password hash in the globally readable file `/etc/motioneye/motion.conf` by default. This allows any local user with shell access to easily retrieve these credentials, significantly lowering the barrier for full administrator account takeover in multi-user environments. Successful exploitation can lead to full account compromise, persistence by changing passwords, data enumeration, destruction, and exfiltration.

## Attack Chain

1.  An attacker gains local shell access to a system running a vulnerable motionEye instance.
2.  The attacker accesses the globally readable file `/etc/motioneye/motion.conf` to retrieve the admin username and its corresponding password hash.
3.  The attacker uses a web browser's developer tools or a cookie editor to prepare for setting specific cookies for the motionEye web application.
4.  The attacker manually sets the `meye_username` cookie to the retrieved admin username value.
5.  The attacker manually sets the `meye_password_hash` cookie to the retrieved admin password hash value.
6.  The attacker navigates to the motionEye web interface in their browser.
7.  The motionEye application trusts the client-supplied cookie values (`meye_username` and `meye_password_hash`) without performing server-side validation against a session or proper authentication checks.
8.  The attacker is successfully authenticated as the administrator user, bypassing the standard login process and gaining full control.

## Impact

This critical vulnerability allows attackers to gain full administrative control over affected motionEye deployments. If an attacker has knowledge of a username and password hash (either through prior compromise or local access to `/etc/motioneye/motion.conf`), they can bypass the login mechanism entirely. The consequences include full account compromise, the ability for attackers to establish persistence by changing user passwords, enumeration and potential exfiltration of sensitive data, and even the destruction of data. Any organization using motionEye versions prior to 0.44.0 is at risk, particularly in environments where local shell access to the host machine is possible, as it significantly simplifies obtaining the necessary credentials for the bypass.

## Recommendation

*   Patch affected motionEye installations to version 0.44.0 or higher immediately to mitigate CVE-2026-46488.
*   Implement the provided Sigma rule "Detect motionEye Admin Credential File Access" to monitor for suspicious access to `/etc/motioneye/motion.conf`.
*   Review and restrict file permissions for the `/etc/motioneye/motion.conf` file (referencing the IOC `file_path: /etc/motioneye/motion.conf`) to only allow the motionEye service user to read it, if patching is not immediately feasible.
*   Enable comprehensive logging for file access events on Linux systems to detect reads of sensitive configuration files like `/etc/motioneye/motion.conf`.
