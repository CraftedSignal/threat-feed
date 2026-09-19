---
title: Unauthenticated Arbitrary File Upload in Gravity Forms
slug: 2026-09-gravity-forms-rce
description: The Gravity Forms WordPress plugin (<= 3.1.0.4) is susceptible to unauthenticated remote code execution due to a validation flaw in the upload_file function allowing hidden file upload fields to bypass extension checks.
date: "2026-09-19T04:08:31Z"
lastmod: "2026-09-19T21:59:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rocketgenius:gravity_forms:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=D48A2A44-5438-5A55-BB24-83D12D1BEF4A&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - wordpress
  - arbitrary-file-upload
  - rce
vendors:
  - Rocketgenius
products:
  - Gravity Forms (<= 3.1.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: Exploitation requires the targeted form to contain a File Upload field with its Visibility set to 'Hidden'; the vulnerability is reachable by unauthenticated attackers.
    confidence_band: high
cves:
  - id: CVE-2026-84434
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84434
  - https://sploitus.com/exploit?id=D48A2A44-5438-5A55-BB24-83D12D1BEF4A&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-84434 Exploitation - Suspicious File Upload to Gravity Forms
    description: Detects potential exploitation attempts of CVE-2026-84434 by identifying requests to common Gravity Forms endpoints involving suspicious file extensions via POST methods.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
      - T1505.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Gravity Forms to a version beyond 3.1.0.4
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in versions up to 3.1.0.4
  hunt_leads:
    - lead: Search web logs for POST requests to form endpoints containing .php or .phtml in arguments
      technique_id: T1505.002
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Arbitrary file upload leads to RCE via executable files
  mitigation_plan:
    - priority: immediate
      action: Disable File Upload fields with Hidden visibility on all public Gravity Forms
      owner: IT Operations
      addresses: CVE-2026-84434
      evidence: Exploitation requires File Upload field with Hidden visibility
updates:
  - at: "2026-09-19T21:59:26Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=D48A2A44-5438-5A55-BB24-83D12D1BEF4A&utm_source=rss&utm_medium=rss
---

Gravity Forms, a popular form-building plugin for WordPress, contains a critical vulnerability (CVE-2026-84434) in versions up to and including 3.1.0.4. The flaw exists within the upload_file() function and stems from a validation bypass when processing File Upload fields configured with 'Hidden' visibility. Because the field validation pipeline and file persistence pipeline operate independently, hidden fields are not subjected to the same extension restrictions as standard fields. Furthermore, rejected files may still be processed by the upload_file() function without secondary validation, enabling unauthenticated remote attackers to upload executable scripts to the web server. Successful exploitation facilitates remote code execution (RCE) on the underlying WordPress environment, representing a severe risk for any site utilizing hidden file upload components on public-facing forms.

## Attack Chain

1. Attacker identifies a target WordPress site running a vulnerable version of Gravity Forms.
2. Attacker probes the site to discover publicly accessible forms containing File Upload fields with 'Hidden' visibility.
3. Attacker crafts a malicious HTTP POST request targeting the form submission endpoint, embedding a webshell (e.g., .php extension) within the hidden file field.
4. The plugin's validation pipeline fails to apply standard extension restrictions due to the field's 'Hidden' status.
5. The file data is passed to the upload_file() function for persistence.
6. The web server saves the attacker-supplied file to a reachable directory.
7. Attacker executes the uploaded file via a direct HTTP request to the stored location.
8. Attacker gains RCE and proceeds with further post-exploitation activities.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code on the web server. This leads to full site compromise, potential data exfiltration of user records or database contents, and the installation of persistent backdoors or web shells, affecting any WordPress environment utilizing vulnerable versions of the plugin.

## Recommendation

- Immediately upgrade the Gravity Forms plugin to the latest patched version available.
- Audit all active Gravity Forms on public-facing pages for File Upload fields with 'Hidden' visibility.
- Temporarily disable File Upload fields in public forms until the plugin is updated.
- Monitor web server access logs for anomalous POST requests to form submission endpoints followed by immediate requests to newly created files in the uploads directory.
