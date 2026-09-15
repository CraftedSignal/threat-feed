---
title: Path Traversal Vulnerability in Flextype CMS Entries REST API
slug: 2026-09-flextype-cms-traversal
description: Flextype CMS versions through 1.0.0-alpha.3 are vulnerable to path traversal via the Entries REST API, allowing authenticated attackers to read, create, or overwrite arbitrary files on the filesystem.
date: "2026-09-15T01:38:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flextype:cms:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-vulnerability
  - cve-2026-91751
vendors:
  - Flextype
products:
  - Flextype CMS (<= 1.0.0-alpha.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Flextype CMS through 1.0.0-alpha.3 fails to properly validate id and new_id parameters in the Entries REST API, allowing API token holders to read, create, or overwrite files outside the entries directory.
    confidence_band: high
cves:
  - id: CVE-2026-91751
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91751
rules:
  - title: Detects CVE-2026-91751 Exploitation - Path Traversal in Entries REST API
    description: Detects attempts to exploit CVE-2026-91751 by monitoring for path traversal sequences in the 'id' or 'new_id' parameters within REST API requests.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Flextype CMS to version > 1.0.0-alpha.3
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in versions through 1.0.0-alpha.3
  hunt_leads:
    - lead: Search web logs for traversal patterns in API paths
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Path traversal vulnerability in API endpoints
  mitigation_plan:
    - priority: immediate
      action: Block unauthorized or suspicious API requests targeting /entries/ endpoints
      owner: IT Operations
      addresses: CVE-2026-91751
      evidence: NVD vulnerability details
---

Flextype CMS versions up to and including 1.0.0-alpha.3 contain a critical path traversal vulnerability (CVE-2026-91751) within the Entries REST API. The vulnerability stems from insufficient input validation of the 'id' and 'new_id' parameters when processing API requests. This flaw permits an attacker who possesses a valid API token to escape the intended project entries directory. By utilizing path traversal sequences, an attacker can navigate the filesystem to read sensitive configuration or application files, or create and overwrite files in arbitrary directories. Given the potential for arbitrary file creation and modification, successful exploitation could lead to full system compromise or remote code execution depending on the attacker's ability to inject payloads into executable paths or configuration files.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to the underlying filesystem of the server hosting Flextype CMS. This represents a significant risk to the integrity and confidentiality of the entire hosting environment, as it grants API token holders the ability to read sensitive data, corrupt application files, or potentially gain further control over the host via arbitrary file write operations.

## Recommendation

Prioritized actions for detection and remediation teams:

- Upgrade Flextype CMS installations to a version beyond 1.0.0-alpha.3 immediately to address CVE-2026-91751.
- Audit existing API tokens to ensure only necessary users maintain access and revoke any suspected compromised tokens.
- Monitor web server access logs for anomalous requests containing path traversal patterns (e.g., ../) targeting the Entries REST API endpoints.
- Restrict access to the Entries REST API at the network or web server configuration level for untrusted network segments.
