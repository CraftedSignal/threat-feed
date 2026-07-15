---
title: Gravity Forms Directory Traversal Vulnerability (CVE-2026-12997)
slug: 2026-07-gravity-forms-directory-traversal
description: Unauthenticated attackers can exploit a Directory Traversal vulnerability (CVE-2026-12997) in the Gravity Forms plugin for WordPress, affecting all versions up to and including 2.10.4, to read arbitrary files on the server and receive their contents as an email attachment, potentially exfiltrating sensitive information.
date: "2026-07-15T19:18:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - web-vulnerability
  - collection
  - network
vendors:
  - Gravity Forms
  - WordPress
products:
  - Gravity Forms plugin (< 2.10.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitation requires the targeted form to not enforce login (so publicly accessible), which allows the unauthenticated attacker to reach the process_send_resume_link endpoint
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.
    confidence_band: high
cves:
  - id: CVE-2026-12997
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12997
rules:
  - title: Detects CVE-2026-12997 Exploitation - Gravity Forms Directory Traversal
    description: Detects exploitation attempts against CVE-2026-12997 in Gravity Forms plugin via directory traversal in gform_uploaded_files parameter to read arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical directory traversal vulnerability, tracked as CVE-2026-12997, exists in the Gravity Forms plugin for WordPress, impacting all versions up to and including 2.10.4. This flaw allows unauthenticated attackers to read arbitrary files from the server's filesystem by manipulating the `gform_uploaded_files` parameter. Exploitation requires the targeted WordPress form to be publicly accessible, meaning it does not enforce login for submission. Attackers can leverage the `process_send_resume_link` endpoint to supply an arbitrary email address. Upon successful exploitation, the contents of the traversed file are sent as an attachment to the attacker's specified email, enabling the exfiltration of sensitive configuration files, credentials, or other critical data. This vulnerability poses a significant risk to the confidentiality of data on affected WordPress installations.

## Attack Chain

1. Attacker identifies a WordPress website running the vulnerable Gravity Forms plugin (version <= 2.10.4).
2. Attacker discovers a publicly accessible Gravity Forms form on the target WordPress site that does not require user authentication for submission.
3. Attacker crafts an HTTP POST request targeting a Gravity Forms AJAX endpoint, specifically related to the `process_send_resume_link` action.
4. The request includes a manipulated `gform_uploaded_files` parameter containing a directory traversal payload (e.g., `../../../../etc/passwd` or `..\..\..\..\windows\system32\win.ini`).
5. The attacker specifies an arbitrary email address in the request, intending to receive the exfiltrated file content.
6. The vulnerable Gravity Forms plugin processes the request, misinterpreting the directory traversal path and reading the content of the specified arbitrary file from the server.
7. The plugin generates an email notification containing the read file's content as an attachment.
8. The email is sent to the attacker-controlled address, successfully exfiltrating the arbitrary server file.

## Impact

Successful exploitation of CVE-2026-12997 grants unauthenticated attackers the ability to read any file on the compromised web server that the web server process has permissions to access. This can lead to the exfiltration of highly sensitive information, such as database credentials, API keys, configuration files, source code, and potentially system-level files like `/etc/passwd` or `boot.ini`. The compromise of such data can enable further attacks, including database access, privilege escalation, or full server compromise, severely impacting the confidentiality and integrity of the affected WordPress site and its underlying infrastructure.

## Recommendation

* Patch CVE-2026-12997 immediately by updating the Gravity Forms plugin to version 2.10.5 or newer.
* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-12997.
* Monitor web server access logs for suspicious HTTP POST requests to Gravity Forms AJAX endpoints containing directory traversal patterns in the `gform_uploaded_files` parameter.
* Review email logs and alerts for unexpected outbound emails containing attachments or originating from the Gravity Forms plugin, particularly those not associated with legitimate form submissions.
