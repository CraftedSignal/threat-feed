---
title: Stored XSS Vulnerability in Bludit CMS
slug: 2026-09-bludit-xss
description: Bludit CMS version 3.22.0 contains a stored XSS vulnerability in its SVG upload process, allowing attackers to execute arbitrary JavaScript via malicious XML processing instructions.
date: "2026-09-01T14:31:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - webapps
  - xss
  - injection
vendors:
  - Bludit
products:
  - Bludit CMS (3.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Bludit CMS version 3.22.0 is vulnerable to a stored cross-site scripting (XSS) attack via the image upload functionality.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: Uploading an SVG with <?xml-stylesheet?> XSLT (method=html) results in stored XSS when the file is opened.
    confidence_band: med
references:
  - https://www.exploit-db.com/exploits/52670
rules:
  - title: Detect Malicious SVG Uploads with XML Stylesheet
    description: Detects attempts to upload SVG files containing XML processing instructions commonly used for XSS in Bludit CMS
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web server logs for suspicious SVG uploads using the provided Sigma rule logic.
      owner: Detection Engineering
      due: 24h
      evidence: Exploit-DB 52670 details the specific upload path and payload structure.
  mitigation_plan:
    - priority: immediate
      action: Update Bludit CMS to a version where sanitization logic has been verified to handle XML processing instructions.
      owner: IT Operations
      addresses: Bludit CMS (3.22.0)
      evidence: The source confirms version 3.22.0 is affected.
---

Bludit CMS version 3.22.0 is susceptible to a stored Cross-Site Scripting (XSS) vulnerability due to incomplete sanitization of SVG files. The application's `sanitizeSVG()` function fails to remove XML processing instructions, specifically the `<?xml-stylesheet?>` directive. An attacker can craft a malicious SVG file containing an XSLT transformation that points to a local or remote stylesheet. When this file is uploaded through the administrative interface and subsequently viewed by a user, the XSLT processor executes the embedded JavaScript. This allows an attacker to achieve unauthorized script execution in the context of the user's browser, which can lead to session hijacking, administrative credential theft, or further actions performed on behalf of the victim.

## Attack Chain

1. Attacker authenticates as an administrative user or gains access to the image upload endpoint.
2. Attacker crafts a malicious SVG file containing an `<?xml-stylesheet?>` XML processing instruction.
3. Attacker embeds an XSLT transformation within the SVG that includes a `<script>` block containing the desired JavaScript payload.
4. Attacker sends a `POST` request to `/admin/ajax/upload-images` with the malicious SVG file as a multipart/form-data payload.
5. The application fails to strip the XML processing instructions in `sanitizeSVG()` and stores the file in `/bl-content/uploads/`.
6. The attacker or a victim navigates to the URL of the uploaded SVG file.
7. The browser renders the SVG, triggers the XSLT stylesheet, and executes the embedded JavaScript payload.

## Impact

Successful exploitation allows for arbitrary code execution in the victim's browser session. If an administrator is tricked into viewing the malicious file, the attacker can perform unauthorized administrative actions, modify site content, or steal session cookies, potentially leading to full site compromise.

## Recommendation

Prioritized actions for security teams:
- Verify your Bludit CMS version and upgrade to a patched release if available.
- Implement strict server-side content-type validation and disable the execution of XML processing instructions for user-uploaded SVG files.
- Use Content Security Policy (CSP) headers to restrict script execution for content hosted on the site's media storage domain.
- Deploy the suggested web server detection rule to monitor for suspicious file uploads containing XML stylesheet references.
