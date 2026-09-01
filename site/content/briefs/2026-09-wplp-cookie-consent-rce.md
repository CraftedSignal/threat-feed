---
title: Unauthenticated Remote Code Execution in WPLP Cookie Consent Plugin
slug: 2026-09-wplp-cookie-consent-rce
description: The WPLP Cookie Consent WordPress plugin is vulnerable to unauthenticated arbitrary file upload due to improper authorization and missing file type validation, enabling remote code execution.
date: "2026-09-01T05:02:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wordpress:wplp_cookie_consent_cookie_banner_consent_management_for_gdpr_ccpa_google_consent_mode:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - remote-code-execution
  - cve-2026-75865
vendors:
  - WordPress
products:
  - WPLP Cookie Consent – Cookie Banner & Consent Management for GDPR, CCPA & Google Consent Mode (<= 4.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WPLP Cookie Consent – Cookie Banner & Consent Management for GDPR, CCPA & Google Consent Mode plugin for WordPress is vulnerable to arbitrary file upload due to missing file type validation in the saas_upload_logo() function combined with an authorization bypass on the WPLP connector REST endpoints in all versions up to, and including, 4.4.1.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-75865
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75865
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update WPLP Cookie Consent plugin to a version > 4.4.1
      owner: IT Operations
      due: 24h
      evidence: Plugin version 4.4.1 and earlier are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Update WPLP Cookie Consent to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-75865
      evidence: Source explicitly names vulnerable versions up to 4.4.1.
---

The WPLP Cookie Consent - Cookie Banner & Consent Management for GDPR, CCPA & Google Consent Mode plugin for WordPress (versions 4.4.1 and earlier) contains a critical security flaw allowing unauthenticated remote code execution (RCE). The vulnerability stems from a broken access control mechanism on the plugin's REST API connector endpoints, coupled with a lack of input validation within the saas_upload_logo() function. By bypassing authentication, an attacker can invoke the logo upload functionality to transmit arbitrary files, such as malicious PHP scripts, directly to the web server's filesystem. Once uploaded, these files can be executed by navigating to the file path, granting the attacker a persistent foothold on the affected WordPress site.

## Attack Chain

1. Attacker identifies a target running WPLP Cookie Consent plugin version 4.4.1 or lower.
2. Attacker probes the REST API endpoints associated with the plugin to locate the vulnerable connector service.
3. Attacker triggers the authorization bypass on the target REST endpoint, gaining unauthorized access to plugin functionality.
4. Attacker sends an HTTP POST request targeting the saas_upload_logo() function.
5. Attacker includes a malicious payload (e.g., a web shell disguised as an image file) in the file upload request.
6. Server fails to validate the file extension or content, saving the payload to a publicly accessible directory.
7. Attacker navigates to the URL of the uploaded file to trigger its execution on the server.
8. Attacker achieves remote code execution for system compromise or further lateral movement.

## Impact

Successful exploitation of CVE-2026-75865 allows unauthenticated actors to gain full control over the compromised WordPress server. This can lead to complete site compromise, data exfiltration of customer information, unauthorized site defacement, and the deployment of additional malware or backdoors. Given the ubiquity of cookie consent management plugins, a large number of internet-facing sites may be at risk.

## Recommendation

Prioritize the update of the WPLP Cookie Consent plugin to the latest version, ensuring all installations are patched beyond version 4.4.1.

## Rules

title: "Detects CVE-2026-75865 Exploitation - Unauthenticated File Upload via WPLP REST API"
description: "Detects exploitation attempts by monitoring for POST requests to the plugin's logo upload endpoint. High-risk indicators include requests lacking session headers or containing non-image file extensions."
logsource:
 category: webserver
detection:
 selection:
 cs-method: "POST"
 cs-uri-stem|contains: "/wp-json/"
 cs-uri-query|contains: "saas_upload_logo"
 filter:
 cs-uri-query|endswith:
 - ".jpg"
 - ".jpeg"
 - ".png"
 - ".gif"
 condition: selection and not filter
level: critical
tags:
 - attack.initial_access
 - attack.execution
 - attack.t1190
 - attack.t1203
tests:
 positive:
 - name: "Malicious upload to logo endpoint"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/wp-json/wplp/v1/upload"
 cs-uri-query: "action=saas_upload_logo&filename=shell.php"
 negative:
 - name: "Legitimate logo upload"
 data:
 - cs-method: "POST"
 cs-uri-stem: "/wp-json/wplp/v1/upload"
 cs-uri-query: "action=saas_upload_logo&filename=logo.png"
falsepositives:
 - "Legitimate administrative file uploads if the webserver path mapping is inconsistent"
handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "webserver"
 event_or_channel: "access_logs"
 required_fields:
 - "cs-method"
 - "cs-uri-stem"
 - "cs-uri-query"
 availability: "available"
 validation:
 status: "needs_environment_validation"
