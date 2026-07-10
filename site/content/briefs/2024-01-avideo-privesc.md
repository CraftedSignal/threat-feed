---
title: WWBN AVideo Unauthenticated Privilege Escalation via CSRF (CVE-2026-33649)
slug: 2024-01-avideo-privesc
description: WWBN AVideo platform versions up to 26.0 are vulnerable to privilege escalation via a CSRF vulnerability in the `plugin/Permissions/setPermission.json.php` endpoint, allowing an unauthenticated attacker to escalate privileges to near-admin access.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - privilege-escalation
  - csrf
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33649
rules:
  - title: AVideo Privilege Escalation Image Request
    description: Detects suspicious GET requests to the `plugin/Permissions/setPermission.json.php` endpoint, potentially indicating a CSRF attack attempting to escalate privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: AVideo Privilege Escalation Cookie Setting
    description: Detects when the `session.cookie_samesite` attribute is set to 'None' in HTTP responses, a configuration that increases the risk of CSRF attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open source video platform, is vulnerable to an unauthenticated privilege escalation vulnerability (CVE-2026-33649) in versions up to and including 26.0. The vulnerability exists within the `plugin/Permissions/setPermission.json.php` endpoint, which lacks CSRF token validation. Furthermore, the application explicitly sets `session.cookie_samesite=None` on session cookies, making it susceptible to cross-site request forgery (CSRF) attacks. An attacker can exploit this by crafting a malicious HTML page containing `<img>` tags that, when visited by an authenticated administrator, silently grant arbitrary permissions to a user group controlled by the attacker. This results in the attacker gaining near-administrator privileges on the AVideo platform. There is currently no patched version available.

## Attack Chain

1. Attacker identifies a vulnerable AVideo instance running version 26.0 or earlier.
2. Attacker registers a low-privilege user account on the AVideo platform.
3. Attacker crafts a malicious HTML page containing multiple `<img>` tags. Each `<img>` tag's `src` attribute points to the vulnerable `plugin/Permissions/setPermission.json.php` endpoint on the target AVideo instance.
4. The GET parameters within the `src` attribute of the `<img>` tags are constructed to grant specific administrative permissions to the attacker's user group. This includes permissions to manage users, videos, plugins, and other sensitive settings.
5. The attacker social engineers an administrator of the AVideo instance to visit the malicious HTML page. This could be achieved through phishing or by hosting the page on a website likely to be visited by the admin.
6. When the administrator visits the page, their browser automatically sends HTTP GET requests to the AVideo instance for each `<img>` tag. Because `session.cookie_samesite` is set to `None` and no CSRF token is required, the administrator's session cookie is sent with these requests.
7. The AVideo server processes these requests as if they were legitimate actions performed by the administrator, granting the specified permissions to the attacker's user group.
8. The attacker logs into their low-privilege account and now has elevated privileges, allowing them to perform administrative tasks such as modifying system settings, uploading malicious videos, or creating new administrator accounts.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to gain near-administrator level access to the AVideo platform. This can lead to complete compromise of the platform, including unauthorized modification of video content, access to sensitive user data, and the ability to inject malicious code into the platform. The lack of a patched version means all vulnerable AVideo instances are at risk until an update is released and applied. The severity is high due to the ease of exploitation and the significant impact on confidentiality, integrity, and availability.

## Recommendation

*   Deploy the Sigma rule `AVideo_Privilege_Escalation_Image_Request` to detect suspicious requests to the `plugin/Permissions/setPermission.json.php` endpoint in your web server logs.
*   Deploy the Sigma rule `AVideo_Privilege_Escalation_Cookie_Setting` to detect instances where `session.cookie_samesite` is explicitly set to `None` in the application's HTTP responses, which is the prerequisite for this CSRF exploit.
*   Monitor web server logs for unexpected GET requests to the `plugin/Permissions/setPermission.json.php` endpoint originating from unusual referrers or user agents.
*   Until a patch is released, implement a temporary mitigation by adding CSRF protection to the `plugin/Permissions/setPermission.json.php` endpoint. This may require code modifications.
*   Apply available patches as soon as they are released by WWBN for AVideo to address CVE-2026-33649.
