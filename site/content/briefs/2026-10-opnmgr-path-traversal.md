---
brief_id: brief-2026-10-23-opnmgr-path-traversal
event_id: brief-2026-10-23-opnmgr-path-traversal
revision: 1
activity_at: "2026-10-23T16:37:42Z"
title: 'OPNMGR: Unauthenticated path traversal (CVE-2026-103978)'
slug: 2026-10-opnmgr-path-traversal
description: OPNMGR versions prior to 3.10.0 are vulnerable to an unauthenticated path traversal attack in the snyk_scan_progress.php file, allowing remote attackers to read sensitive .json files on the server.
date: "2026-10-23T16:37:42Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:opnmgr_project:opnmgr:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - path-traversal
  - php
  - opnsense
vendors:
  - OPNMGR
products:
  - OPNMGR (< 3.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated path traversal in OPNMGR's snyk_scan_progress.php allows arbitrary .json read.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: By manipulating the scan_id parameter, an attacker can bypass directory restrictions to read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-103978
    kev_status: unknown
references:
  - https://github.com/agit8or1/OPNMGR/security/advisories/GHSA-8x7v-vwpx-3wr7
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-103978
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KIWKNR-CVE-2026-103978&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-103978 Exploitation - Unauthenticated Path Traversal
    description: Detects attempts to access arbitrary files via the snyk_scan_progress.php endpoint using directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
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
    - action: Patch OPNMGR to v3.10.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Maintainer shipped the fix in v3.10.0.
  hunt_leads:
    - lead: Identify access patterns to snyk_scan_progress.php involving directory traversal.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Entry point scan_id parameter is used to perform path traversal.
  mitigation_plan:
    - priority: immediate
      action: Apply patch v3.10.0.
      owner: IT Operations
      addresses: CVE-2026-103978
      evidence: Maintainer shipped the fix in v3.10.0.
---

OPNMGR, a PHP-based OPNsense fleet manager, contains a critical path traversal vulnerability (CVE-2026-103978) in the 'snyk_scan_progress.php' endpoint. The endpoint fails to perform authentication or input sanitization on the 'scan_id' parameter, which is concatenated directly into a file path and passed to 'file_get_contents()'. Because the application forces a '.json' file extension, attackers can only retrieve files ending in this extension. However, this is sufficient to access sensitive files such as configuration files, service account credentials, and API keys. The vulnerability was disclosed via GitHub Security Advisory GHSA-8x7v-vwpx-3wr7 and fixed in version 3.10.0.

## Impact

Successful exploitation allows an unauthenticated remote attacker to read arbitrary '.json' files accessible by the web server (typically 'www-data'). In the context of OPNMGR, this poses a high risk of exposing firewall API keys, service credentials, and internal configuration secrets.

## Recommendation

- Upgrade OPNMGR to version 3.10.0 or later immediately.
- Implement access control lists (ACLs) to restrict network access to the OPNMGR web root if immediate patching is not possible.
- Audit logs for the 'snyk_scan_progress.php' endpoint for anomalous 'scan_id' requests containing directory traversal sequences (e.g., '..').
