---
title: Connect CMS Form Plugin Stored XSS Vulnerability
slug: 2024-01-connect-cms-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the file field of the Form Plugin in Connect CMS versions 1.x series <= 1.41.0 and 2.x series <= 2.41.0, allowing arbitrary script execution in an administrator's browser, potentially leading to unauthorized actions or information theft.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - connect-cms
  - stored-xss
  - vulnerability
  - form-plugin
vendors:
  - Connect
products:
  - Connect CMS
  - Form Plugin
references:
  - https://github.com/advisories/GHSA-mv3p-7p89-wq9p
rules:
  - title: Detect Connect CMS XSS Attempt via HTTP Request
    description: Detects potential attempts to exploit the Connect CMS Form Plugin XSS vulnerability (CVE-2026-32278) by identifying suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Connect CMS XSS Attempt via Uploaded File Extension
    description: Detects attempts to upload files with extensions that could be used to trigger an XSS vulnerability in Connect CMS.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability has been identified in the file field of the Form Plugin for Connect CMS. This flaw affects versions 1.x up to and including 1.41.0, as well as versions 2.x up to and including 2.41.0. Successfully exploiting this vulnerability could enable an attacker to inject and execute arbitrary JavaScript code within an administrator's browser session. This could lead to unauthorized actions being performed on the CMS, such as modifying website content, creating new administrative accounts, or stealing sensitive information managed within the CMS. The vulnerability was reported by Sho Odagiri of GMO Cybersecurity by Ierae, Inc. and is tracked as CVE-2026-32278. Users of Connect CMS are advised to update to versions 1.41.1 or 2.41.1 to mitigate the risk.

## Attack Chain

1. An attacker identifies a Connect CMS instance running a vulnerable version of the Form Plugin (<= 1.41.0 or <= 2.41.0).
2. The attacker crafts a malicious payload containing JavaScript code designed to execute harmful actions within an administrator's session.
3. The attacker utilizes the file upload field of the Form Plugin to inject the malicious payload. This may involve uploading a file with a specially crafted name or content designed to trigger the XSS vulnerability.
4. An administrator accesses the Form Plugin interface or views the uploaded file, triggering the stored XSS vulnerability.
5. The attacker's JavaScript payload executes within the administrator's browser session.
6. The injected script steals the administrator's session cookie or other authentication tokens.
7. The attacker uses the stolen credentials to authenticate to the Connect CMS as the administrator.
8. The attacker performs unauthorized actions, such as modifying website content, installing malicious plugins, or exfiltrating sensitive data.

## Impact

Successful exploitation of this stored XSS vulnerability can have significant consequences for Connect CMS users. An attacker could gain complete control over the affected CMS instance, leading to website defacement, data breaches, and the installation of backdoors for persistent access. Because the XSS triggers in an administrator's browser, the attacker inherits administrative privileges, allowing them to perform any action an administrator can. This could affect a wide range of websites using Connect CMS, potentially impacting numerous organizations. The severity is high due to the ease of exploitation and the potential for widespread damage.

## Recommendation

*   Immediately update Connect CMS to version 1.41.1 or 2.41.1 to patch the XSS vulnerability (CVE-2026-32278).
*   Implement the Sigma rule "Detect Connect CMS XSS Attempt via HTTP Request" to identify potential exploitation attempts targeting this vulnerability.
*   Enable web server access logging to monitor for suspicious HTTP requests associated with XSS attacks, which is required for the Sigma rule to function.
