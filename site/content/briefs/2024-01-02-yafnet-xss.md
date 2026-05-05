---
title: YAFNET Unauthenticated Stored XSS via User-Agent Header
slug: 2024-01-02-yafnet-xss
description: YAFNET is vulnerable to an unauthenticated stored second-order XSS vulnerability in the admin event log, triggered by a reflected `User-Agent` header, allowing an attacker to execute arbitrary JavaScript in an administrator's session.
date: "2026-05-05T20:31:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - web-application
  - injection
vendors:
  - YetAnotherForum.NET
products:
  - YAFNET.Core
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-33gv-fc78-qgf5
rules:
  - title: Detect YAFNET XSS in Event Log
    description: Detects attempts to inject XSS payloads via the User-Agent header targeting the YAFNET application which could result in stored XSS.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect YAFNET Event Log Access
    description: Detects access to the YAFNET admin event log page, which could indicate an administrator viewing a stored XSS payload.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

YAFNET is vulnerable to a stored (second-order) cross-site scripting (XSS) vulnerability. An unauthenticated attacker can inject malicious JavaScript code into the `User-Agent` header of an HTTP request. This input is then logged into the `EventLog.Description` column of the database whenever an error occurs on the server. The admin event log page deserializes the JSON and displays the `UserAgent` value without proper encoding. When an administrator views the event log page, the injected JavaScript is executed in the administrator's browser session, potentially leading to account takeover or other malicious activities. This vulnerability affects YAFNET.Core versions 4.0.0-beta01 through 4.0.4 and versions up to 3.2.11. The vulnerability was reported on 2026-05-05 and assigned CVE-2026-43938.

## Attack Chain

1. An unauthenticated attacker sends a malicious HTTP request to the `/api/Attachments/GetAttachment` endpoint with a crafted `User-Agent` header containing XSS payload (e.g., `<img src=x onerror=alert('XSS')>`).
2. The YAFNET application encounters an error when processing the request, triggering an exception.
3. The `YAFNET.Core/Logger/DbLogger.cs` captures the request's `User-Agent` header.
4. The `User-Agent` string is serialized into a JSON object using `JsonConvert` and stored in the `EventLog.Description` column of the `dbo.EventLog` table in the database.
5. An administrator navigates to the `/Admin/EventLog` page.
6. The `YetAnotherForum.NET/Pages/Admin/EventLog.cshtml.cs` deserializes the JSON from the `EventLog.Description` column.
7. The `FormatStackTrace()` function extracts the `UserAgent` value from the deserialized JSON.
8. The `EventLog.cshtml` Razor view uses `@Html.Raw` to render the `UserAgent` value directly into the HTML, without proper encoding, resulting in the execution of the attacker-controlled JavaScript in the administrator's browser.

## Impact

A successful XSS attack can allow an unauthenticated attacker to execute arbitrary JavaScript code in the context of an administrator's session. This can lead to a complete forum takeover, including creating new administrative accounts, modifying site-wide settings, and exfiltrating user data from admin-only endpoints. Due to the unauthenticated nature of the vulnerability, it is readily exploitable at scale and may be automated.

## Recommendation

*   Apply the patch or upgrade to a version of YAFNET.Core later than 4.0.4 or greater than 3.2.11 to remediate the XSS vulnerability described in CVE-2026-43938.
*   Deploy the Sigma rule "Detect YAFNET XSS in Event Log" to your SIEM to identify potential exploitation attempts targeting the `User-Agent` header.
*   Monitor web server logs for requests to `/api/Attachments/GetAttachment` with suspicious `User-Agent` headers.
