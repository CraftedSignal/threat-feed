---
title: AVideo Meet Plugin Authorization Bypass via Filename Parameter
slug: 2026-05-avideo-meet-auth-bypass
description: AVideo's Meet plugin contains an authorization bypass vulnerability in the `uploadRecordedVideo.json.php` endpoint that derives `users_id` from the uploaded filename and calls passwordless `User->login()`, allowing any caller with the Meet shared secret to obtain a session as arbitrary users including admin.
date: "2026-05-15T18:18:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - account-takeover
  - web-application
vendors:
  - composer
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qxvm-r42f-5p8j
  - https://github.com/advisories/GHSA-83xq-8jxj-4rxm
  - https://github.com/advisories/GHSA-4wmm-6qxj-fpj4
rules:
  - title: AVideo Meet Plugin Unauthorized Session Creation
    description: Detects unauthorized session creation in AVideo Meet plugin by monitoring POST requests to uploadRecordedVideo.json.php with filenames containing user IDs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1068
      - T1555
    data_sources:
      - webserver
  - title: AVideo checkToken.json.php Timing Attack Attempt
    description: Detects potential timing attack attempts against the checkToken.json.php endpoint by monitoring request volume from a single source IP.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - webserver
rules_count: 2
---

AVideo is a video-sharing platform with a Meet plugin for video conferencing integration. The `uploadRecordedVideo.json.php` endpoint in the Meet plugin is vulnerable to an authorization bypass. This vulnerability allows an attacker with knowledge of the Meet shared secret to authenticate as any user, including an administrator. The vulnerability stems from the endpoint using the filename of the uploaded video to determine the `users_id` for authentication. An attacker can manipulate this filename to impersonate any user. The shared secret is calculable from the AVideo salt, often leaked via separate path-traversal vulnerabilities (e.g. `GHSA-83xq-8jxj-4rxm` or `GHSA-4wmm-6qxj-fpj4`) or recoverable via timing attack on `checkToken.json.php`. The affected version is AVideo version 29.0 and earlier.

## Attack Chain

1.  Attacker obtains the Meet shared secret through path traversal to read `videos/configuration.php` or by timing attacks against the `checkToken.json.php` endpoint. The secret is derived from `md5($global['systemRootPath'] . $global['salt'] . "meet")`.
2.  Attacker crafts a malicious HTTP POST request to `/plugin/Meet/uploadRecordedVideo.json.php` with the `Authorization: Bearer <Meet secret>` header set.
3.  The POST request includes a multipart body with a file field named `upl`. The attacker sets the filename of the uploaded file to `1-anything.mp4`, where `1` is the target `users_id` (e.g., the admin user).
4.  The server validates the Meet shared secret, but trusts the attacker-controlled filename to determine the `users_id` on line 56 of `plugin/Meet/uploadRecordedVideo.json.php`.
5.  The server instantiates a `User` object using the attacker-provided `users_id` and calls `$userObject->login(true, true)`, triggering the passwordless login path in `objects/user.php`.
6.  The server sets `$_SESSION['user']` to the impersonated user's data, calls `setUserCookie(...)`, and issues a new session ID via `_session_regenerate_id()`.
7.  The HTTP response includes a `Set-Cookie` header with the new `PHPSESSID`.
8.  The attacker uses the captured `PHPSESSID` cookie in subsequent requests to access the AVideo platform as the impersonated user, gaining full control of their account.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to any user account on the AVideo platform, including administrator accounts. This can lead to complete system compromise, data breaches, and denial of service. There is no limit to which `users_id` can be targeted. If the Meet plugin is enabled, all accounts are at risk. An attacker achieving admin privileges can modify video content, access sensitive user data, and manipulate system settings.

## Recommendation

*   Apply the vendor-provided patch to AVideo that includes the suggested fixes to `plugin/Meet/uploadRecordedVideo.json.php` and `objects/user.php` as detailed in the advisory.
*   Deploy the "AVideo Meet Plugin Unauthorized Session Creation" Sigma rule to detect exploitation attempts.
*   Remove the `checkToken.json.php` endpoint or restrict access to administrators only to mitigate the timing attack vector.
*   Monitor web server logs for POST requests to `/plugin/Meet/uploadRecordedVideo.json.php` with unusual filenames in the `upl` file field.
