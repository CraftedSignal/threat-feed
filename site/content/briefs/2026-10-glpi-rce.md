---
brief_id: brief-2026-10-29-glpi-rce
event_id: brief-2026-10-29-glpi-rce
revision: 1
activity_at: "2026-10-29T14:37:42Z"
title: 'GLPI: Remote Code Execution via Local File Inclusion (CVE-2025-24801)'
slug: 2026-10-glpi-rce
description: GLPI versions before 10.0.18 are vulnerable to remote code execution through Local File Inclusion, where authenticated users can modify file extension allowlists to execute arbitrary PHP payloads.
date: "2026-10-29T14:37:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:glpi-project:glpi:*:*:*:*:*:*:*:*
vendors:
  - Glpi-project
products:
  - GLPI (< 10.0.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This exploit uses CVE-2025-24801 to get Remote Code Execution (RCE) via Local File Inclusion (LFI) at GLPI 10.0.17.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Enable PHP extension in Document Types to allow PHP payload upload.
    confidence_band: high
cves:
  - id: CVE-2025-24801
    cvss: 8.5
    epss: 0.21148
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-R1BEIRIN-EXPLOIT-CVE-2025-24801
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-R1BEIRIN-EXPLOIT-CVE-2025-24801&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential CVE-2025-24801 Exploitation
    description: Detects exploitation attempts of CVE-2025-24801 by monitoring POST requests to the documenttype configuration form that contain common PHP-related file extensions in the parameter body.
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
    - action: Upgrade GLPI instances to version 10.0.18 or higher.
      owner: IT Operations
      due: 48h
      evidence: Affected GLPI versions are < 10.0.18.
  hunt_leads:
    - lead: Search web logs for suspicious access to newly uploaded files in directories associated with GLPI document storage.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit achieves RCE by accessing the uploaded PHP file via the web path.
  mitigation_plan:
    - priority: immediate
      action: Patch GLPI to 10.0.18.
      owner: IT Operations
      addresses: CVE-2025-24801
      evidence: Vendor release fixes the LFI vulnerability.
---

GLPI versions prior to 10.0.18 contain a vulnerability (CVE-2025-24801) allowing Remote Code Execution (RCE) via Local File Inclusion. An authenticated user can interact with the `front/documenttype.form.php` endpoint and manipulate the `ext` parameter to permit the upload of unauthorized file types, such as PHP scripts. Successful exploitation results in arbitrary command execution on the host server.

## Attack Chain

1. Attacker authenticates to the GLPI application with low-level privileges.
2. Attacker navigates to the `front/documenttype.form.php` endpoint.
3. Attacker modifies the allowed file extensions configuration for Document Types via the `ext` parameter in the request body.
4. Attacker uploads a malicious PHP file through the application's file upload interface.
5. The application saves the file to a location accessible by the web server.
6. Attacker triggers execution of the uploaded file by navigating to its path, resulting in RCE.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary commands with the privileges of the web server, leading to full compromise of the GLPI application instance.

## Recommendation

- Upgrade GLPI to version 10.0.18 or later immediately to patch CVE-2025-24801.
- Audit GLPI user accounts to identify and restrict low-privileged users with access to configuration-altering endpoints.
- Monitor web server logs for suspicious POST requests to `front/documenttype.form.php` and subsequent direct access to uploaded files in the web-accessible directories.
