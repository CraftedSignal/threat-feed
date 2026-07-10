---
title: ApostropheCMS Stored XSS Vulnerability in SEO Fields Leads to Data Exposure
slug: 2024-01-09-apostrophe-xss
description: A stored cross-site scripting (XSS) vulnerability exists in SEO-related fields (SEO Title and Meta Description) in ApostropheCMS v4.28.0, allowing injection of arbitrary JavaScript into HTML contexts, performing authenticated API requests, and exfiltrating sensitive data, leading to a compromise of application confidentiality.
date: "2024-01-09T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - apostrophecms
  - xss
  - stored-xss
  - data-exfiltration
vendors:
  - ApostropheCMS
products:
  - ApostropheCMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-35569
    cvss: 8.7
    epss: 0.00032
references:
  - https://github.com/advisories/GHSA-855c-r2vq-c292
  - https://youtu.be/FZuulua_pa8
iocs:
  - type: url
    value: https://youtu.be/FZuulua_pa8
  - type: url
    value: http://ATTACKER-IP:5656/?data=BASE64_ENCODED_RESPONSE
ioc_counts:
  url: 2
rules:
  - title: ApostropheCMS XSS in SEO Fields
    description: Detects attempts to inject potentially malicious JavaScript payloads into SEO-related fields (SEO Title and Meta Description) within ApostropheCMS, indicative of a stored XSS vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.007
      - T1189
    data_sources:
      - webserver
      - linux
  - title: ApostropheCMS Sensitive API Access Attempt
    description: Detects attempts to access the sensitive /api/v1/@apostrophecms/user API endpoint which retrieves usernames, email addresses, and roles (including admin), in ApostropheCMS.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability has been identified in ApostropheCMS, specifically affecting version v4.28.0. The vulnerability resides within the SEO Title and Meta Description fields, where user-controlled input is not properly neutralized. An attacker can inject arbitrary JavaScript code into these fields, which is then rendered in HTML contexts such as `<title>` tags, `<meta>` attributes, and structured data (JSON-LD). This injected script executes within the browser of an authenticated user, enabling the attacker to perform actions on their behalf, including making authenticated API requests to retrieve sensitive data such as usernames, email addresses, and roles (including admin), and exfiltrating it to an attacker-controlled server. This can lead to a full compromise of the affected application.

## Attack Chain

1. An attacker logs into ApostropheCMS with an account that has permission to edit pages.
2. The attacker navigates to the page creation or editing interface within the CMS.
3. The attacker enters a malicious JavaScript payload into the SEO Title or Meta Description field. The payload is designed to execute when a user views the page.
4. The attacker saves and publishes the page with the injected XSS payload.
5. An administrator visits the published page via their web browser.
6. The XSS payload executes within the administrator's browser, using the administrator's authenticated session.
7. The JavaScript code makes an authenticated API request to `/api/v1/@apostrophecms/user` to retrieve user data.
8. The response containing sensitive user data (usernames, email addresses, roles) is then base64 encoded and exfiltrated to an attacker-controlled server at `http://ATTACKER-IP:5656/?data=BASE64_ENCODED_RESPONSE`.

## Impact

This vulnerability allows an attacker to execute arbitrary JavaScript code within the context of an authenticated administrator's session in ApostropheCMS. Successful exploitation allows the attacker to access and exfiltrate sensitive user data, including usernames, email addresses, and roles, potentially leading to privilege escalation and complete compromise of the application and its data.  The vulnerability affects ApostropheCMS versions up to and including v4.28.0.

## Recommendation

*   Deploy the "ApostropheCMS XSS in SEO Fields" Sigma rule to detect attempts to inject malicious JavaScript into SEO-related fields (SEO Title and Meta Description).
*   Monitor web server logs for requests containing the specific API endpoint `/api/v1/@apostrophecms/user`, especially if the request is initiated from an unusual or unexpected user agent, based on the log source defined in the Sigma rules.
*   Inspect web server logs for outbound connections to external IPs (ATTACKER-IP) following a request to the vulnerable API endpoint as defined in the iocs section.
*   Apply patches or upgrade ApostropheCMS to a version beyond 4.28.0 to remediate CVE-2026-35569.
