---
brief_id: brief-2026-10-26-mautic-unrestricted-upload
event_id: brief-2026-10-26-mautic-unrestricted-upload
revision: 1
activity_at: "2026-10-26T15:44:34Z"
title: 'Mautic: Unrestricted file upload remote code execution (CVE-2026-115188)'
slug: 2026-10-mautic-unrestricted-upload
description: Mautic 7 allows authenticated users with campaign import permissions to achieve remote code execution by uploading arbitrary malicious files to a publicly accessible directory.
date: "2026-10-26T15:44:34Z"
lastmod: "2026-10-26T15:45:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:mautic:mautic:7:*:*:*:*:*:*:*
  - cpe:2.3:a:mautic:mautic:*:*:*:*:*:*:*:*
tags:
  - webserver
  - rce
  - file-upload
  - cve-2026-115188
vendors:
  - Mautic
products:
  - Mautic (7)
  - Mautic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with permission to create campaign imports can exploit this through the user interface or the API (/api/campaigns/import) to place arbitrary files, including server-side scripts, in the web root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: On web servers that honor per-directory configuration... this leads to remote code execution with the privileges of the web server user.
    confidence_band: high
cves:
  - id: CVE-2026-115188
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-115192
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115188
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115192
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to the campaign import UI and /api/campaigns/import endpoint for all non-essential accounts
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is exploitable via UI and API using authenticated accounts
  hunt_leads:
    - lead: Monitor web server access logs for requests to the media directory containing unexpected file extensions or suspicious script patterns
      technique_id: T1505.004
      data_needed:
        - Web server access logs (Apache/Nginx/IIS)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Files are placed in a publicly accessible media directory
  mitigation_plan:
    - priority: immediate
      action: Implement web server configuration rules to block execution of scripts within the Mautic media upload paths
      owner: IT Operations
      addresses: CVE-2026-115188
      evidence: Exploit relies on web server honoring per-directory configuration to execute uploaded scripts
updates:
  - at: "2026-10-26T15:45:07Z"
    level: L2
    summary: added CVE-2026-115192
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115192
---

Mautic 7 contains an unrestricted file upload vulnerability (CVE-2026-115188) in the campaign import feature. An authenticated user with sufficient permissions can upload arbitrary files through the UI or the /api/campaigns/import endpoint. These files are moved to a publicly accessible media directory without validation of filename or extension. On web server configurations (e.g., Apache) that permit script execution in media directories, this enables remote code execution with the privileges of the web server user.

## Impact
Successful exploitation allows remote code execution on the underlying web server. This results in potential unauthorized access to the Mautic application configuration, environment secrets, and sensitive contact data stored within the database or filesystem.

## Recommendation
1. Identify all Mautic 7 instances within the environment.
2. Restrict campaign import permissions to only trusted, highly vetted service accounts until a vendor patch is applied.
3. Update or apply security hardening to web server configurations to disable script execution (e.g., PHP, Perl) in the Mautic media/upload directories.
4. Review access logs for non-standard file extensions or suspicious filenames being uploaded via the /api/campaigns/import endpoint.
