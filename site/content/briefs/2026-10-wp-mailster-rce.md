---
brief_id: brief-2026-10-21-wp-mailster-rce
event_id: brief-2026-10-21-wp-mailster-rce
revision: 1
activity_at: "2026-10-21T16:08:22Z"
title: 'WP Mailster: Unrestricted file upload remote code execution (CVE-2026-111832)'
slug: 2026-10-wp-mailster-rce
description: WP Mailster versions through 1.9.1.0 contain an unrestricted file upload vulnerability that allows remote attackers to upload web shells and achieve remote code execution.
date: "2026-10-21T16:08:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: No patch details currently available from source; requires monitoring for vendor updates
cpes:
  - cpe:2.3:a:wp-mailster:wp-mailster:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - rce
  - file-upload
vendors:
  - WP Mailster
products:
  - WP Mailster (<= 1.9.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unrestricted Upload of File with Dangerous Type vulnerability in WP Mailster WP Mailster wp-mailster allows Upload a Web Shell to a Web Server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: Unrestricted Upload of File with Dangerous Type vulnerability in WP Mailster WP Mailster wp-mailster allows Upload a Web Shell to a Web Server.
    confidence_band: high
cves:
  - id: CVE-2026-111832
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111832
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory WP Mailster plugin versions and disable affected instances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to 1.9.1.0
  hunt_leads:
    - lead: Anomalous file creation in WordPress upload directories
      technique_id: T1505.003
      data_needed:
        - File system events
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows uploading arbitrary web shells
---

CVE-2026-111832 is an unrestricted file upload vulnerability in the WP Mailster plugin. The flaw allows an attacker to upload arbitrary files, including web shells, which can then be executed by the web server to gain remote code execution. No vendor patch or remediation path is currently specified in the source.

## Impact
Successful exploitation allows for full remote code execution on the underlying web server, providing the attacker with the ability to run arbitrary system commands, access files, and potentially escalate privileges within the environment.

## Recommendation
- Inventory all WordPress instances running the WP Mailster plugin to determine the current version.
- Restrict access to administrative or file-uploading endpoints associated with the WP Mailster plugin using WAF rules or network segmentation until a vendor-supplied patch is applied.
- Monitor web server access logs for anomalous POST requests to plugin directories or suspicious file extensions (e.g., .php, .php5, .phtml) being created in upload directories.
