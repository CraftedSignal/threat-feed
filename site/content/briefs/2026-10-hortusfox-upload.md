---
title: Unrestricted File Upload in HortusFox hortusfox-web
slug: 2026-10-hortusfox-upload
description: HortusFox hortusfox-web through version 6.3 is vulnerable to unrestricted file uploads in the PlantAttachmentModel, allowing authenticated attackers to execute remote code or perform stored cross-site scripting.
date: "2026-10-09T15:31:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hortusfox:hortusfox_web:*:*:*:*:*:*:*:*
vendors:
  - HortusFox
products:
  - hortusfox-web (<= 6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: HortusFox (hortusfox-web) through 6.3 contains an unrestricted file upload vulnerability in PlantAttachmentModel that allows authenticated users to store files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: or PHP files where .htaccess is unenforced to execute code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: Attackers can upload ... PHP files where .htaccess is unenforced to execute code.
    confidence_band: high
cves:
  - id: CVE-2026-108101
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108101
rules:
  - title: Detect CVE-2026-108101 Exploitation - Suspicious File Uploads to HortusFox
    description: Detects exploitation of CVE-2026-108101 by monitoring for unauthorized file uploads targeting the HortusFox attachment endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - IT Operations
  immediate_actions:
    - action: Upgrade hortusfox-web to version 6.4 or later
      owner: IT Operations
      due: 48h
      evidence: Source states version 6.3 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Configure web server to prevent script execution in public/attachments/
      owner: IT Operations
      addresses: CVE-2026-108101
      evidence: Source mentions PHP files executing where .htaccess is unenforced
---

HortusFox (hortusfox-web) versions through 6.3 contain an unrestricted file upload vulnerability in the PlantAttachmentModel. The application fails to properly validate the file extensions of user-supplied attachments when using the /plants/attachments/add endpoint. Authenticated users can upload arbitrary file types, which are subsequently stored in the public/attachments/ directory. If the underlying server environment lacks strict .htaccess enforcement or other execution restrictions, an attacker can upload and execute malicious PHP scripts to gain remote code execution. Additionally, the ability to upload HTML or SVG files permits stored cross-site scripting (XSS) attacks, which could be used to compromise the sessions of other authenticated users or administrators interacting with the application. Defenders should prioritize restricting upload directories and enforcing strict file extension allow-lists on the server side.

## Attack Chain

1. Attacker authenticates to the HortusFox web application with valid user credentials.
2. Attacker navigates to the endpoint /plants/attachments/add for document management.
3. Attacker intercepts the file upload request to modify the file content and extension.
4. Attacker uploads a malicious PHP script or an HTML/SVG file containing XSS payloads.
5. The application saves the file to the public/attachments/ directory without validating the extension.
6. Attacker requests the stored file via the browser or directly accesses the file URL.
7. The server executes the uploaded PHP script or renders the HTML/SVG file in the context of the user session.
8. Attacker gains remote code execution on the web server or successfully executes unauthorized scripts in the browser.

## Impact

Successful exploitation allows authenticated attackers to gain remote code execution (RCE) on the server, potentially leading to a full system compromise. Alternatively, attackers can perform stored XSS to hijack administrator sessions or perform actions on behalf of other users. This vulnerability impacts all installations of hortusfox-web versions 6.3 and earlier.

## Recommendation

1. Upgrade hortusfox-web to a version beyond 6.3 immediately to address the insecure validation in PlantAttachmentModel.
2. Implement server-side execution restrictions on the public/attachments/ directory, ensuring it is configured as a non-executable area (e.g., via web server configuration to disable PHP execution in this path).
3. Deploy a web application firewall (WAF) rule to block POST requests to /plants/attachments/add that contain suspicious file extensions or MIME types not associated with legitimate plant attachments.
