---
brief_id: brief-2026-10-28-wpvivid-rce
event_id: brief-2026-10-28-wpvivid-rce
revision: 1
activity_at: "2026-10-28T08:50:13Z"
title: WPvivid Migration, Backup, Staging arbitrary file upload (CVE-2020-36842)
slug: 2026-10-wpvivid-rce
description: An authenticated remote code execution vulnerability (CVE-2020-36842) in the WPvivid WordPress plugin allows low-privileged users to achieve code execution via ZIP archive file uploads.
date: "2026-10-28T08:50:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:wpvivid:migration_backup_staging:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:wpvivid:migration\,_backup\,_staging:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - rce
  - cve-2020-36842
vendors:
  - WPvivid
products:
  - WPvivid Migration, Backup, Staging (<= 0.9.35)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows authenticated users with low-privileged accounts to upload and extract ZIP archives via the plugin's AJAX API.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: By placing a malicious PHP script inside the uploaded ZIP archive, an attacker can achieve remote code execution (RCE) on the server.
    confidence_band: high
cves:
  - id: CVE-2020-36842
    cvss: 8.8
    epss: 0.01159
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NXPLOITED-CVE-2020-36842
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NXPLOITED-CVE-2020-36842&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2020-36842 Exploitation - Suspicious ZIP File Upload via WPvivid API
    description: Detects exploitation attempts where a user submits a POST request to the WPvivid AJAX API containing zip file markers.
    platform: sigma
    severity: high
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
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress sites running WPvivid Migration, Backup, Staging to identify versions <= 0.9.35.
      owner: IT Operations
      due: 24h
      evidence: Plugin version identified as vulnerable in source.
  hunt_leads:
    - lead: Search web logs for POST requests to admin-ajax.php containing 'action=wpvivid' followed by successful GET requests to .php files in /wp-content/.
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit process involves uploading and subsequently accessing a PHP shell via the web-accessible path.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WPvivid Migration, Backup, Staging plugin to latest version.
      owner: IT Operations
      addresses: CVE-2020-36842
      evidence: Recommended remediation path provided in source.
---

CVE-2020-36842 is an arbitrary file upload vulnerability affecting the WPvivid Migration, Backup, Staging plugin for WordPress versions 0.9.35 and earlier. The flaw resides in the plugin's AJAX API, which allows authenticated users with subscriber-level privileges or higher to upload and extract arbitrary ZIP archives. By crafting a ZIP archive containing a PHP web shell, an attacker can extract malicious files to the web directory and achieve remote code execution (RCE).

## Attack Chain

1. Attacker authenticates to the target WordPress site using a valid low-privileged account (Subscriber or above).
2. Attacker interacts with the WPvivid plugin AJAX API to initiate a file upload.
3. Attacker uploads a crafted ZIP archive containing a malicious PHP script.
4. Attacker triggers the plugin's import or extraction function via the AJAX API.
5. The plugin extracts the ZIP content, including the malicious PHP shell, to the server's web-accessible path (typically /wp-content/).
6. Attacker accesses the uploaded PHP script directly via a browser to execute arbitrary commands.

## Impact

Successful exploitation allows authenticated users to achieve full remote code execution on the underlying server, potentially leading to unauthorized data access, site defacement, or further lateral movement within the hosting environment.

## Recommendation

- Upgrade the WPvivid Migration, Backup, Staging plugin to the latest version immediately to remediate the vulnerability.
- Review WordPress user account permissions and restrict access to the WPvivid plugin functionality to administrative roles only.
- Implement server-side configurations to prevent direct script execution in the 'wp-content/uploads' directory using .htaccess or Nginx configuration blocks.
- Audit server access logs for anomalous POST requests to the WPvivid AJAX API followed by GET requests to newly created files in the /wp-content/ directory.
