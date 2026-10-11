---
title: Path Traversal Vulnerability in pH7Builder
slug: 2026-10-ph7builder-path-traversal
description: Authenticated users can exploit a path traversal vulnerability in the pH7Builder picture module to delete arbitrary files on the server.
date: "2026-10-11T16:03:14Z"
lastmod: "2026-10-11T16:03:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ph7builder:ph7_social_dating_cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - data-exfiltration
  - cve-2026-108905
vendors:
  - pH7Builder
products:
  - pH7 Social Dating CMS (< 18.5.0)
  - pH7 Social Dating CMS (< 18.6.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can supply ../ sequences in the POST picture_link parameter to remove other members' photos or configuration and cache files, causing content loss and denial of service.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'An unauthenticated attacker can bypass API access controls by spoofing the Host header (e.g., setting ''Host: localhost'') and providing the known private_api_key, leading to unauthorized retrieval of sensitive user data.'
    confidence_band: high
cves:
  - id: CVE-2026-108902
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1028902
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108905
rules:
  - title: Detect CVE-2026-108902 Exploitation - Path Traversal in pH7Builder
    description: Detects exploitation attempts by identifying directory traversal sequences in the picture_link parameter within POST requests.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade pH7 Social Dating CMS to 18.5.0 or later.
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure.
  hunt_leads:
    - lead: Search logs for POST requests to the pH7Builder picture module containing '../' or '..\'.
      technique_id: T1499
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source description of path traversal in picture_link.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 18.5.0.
      owner: IT Operations
      addresses: CVE-2026-108902
      evidence: NVD remediation advice.
updates:
  - at: "2026-10-11T16:03:26Z"
    level: L2
    summary: added coverage for pH7 Social Dating CMS (< 18.6.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108905
---

pH7 Social Dating CMS (pH7Builder) versions prior to 18.5.0 contain a critical path traversal vulnerability within the deletePhoto() action of the picture module. An authenticated member can manipulate the picture_link parameter during a file deletion request by injecting directory traversal sequences (such as ../). This flaw allows the attacker to escape the intended directory and delete arbitrary files accessible by the web server process. Successful exploitation can lead to the deletion of configuration files, cache files, or other users' media, resulting in persistent denial of service or disruption of application functionality. Organizations using this CMS should prioritize patching to version 18.5.0 or later to mitigate the risk of unauthorized file deletion and system instability.

## Impact

The vulnerability allows for arbitrary file deletion on the hosting server. This impact is significant for a Content Management System, as attackers can delete critical application configuration files or site content, resulting in immediate service disruption. No specific number of victims is provided, but all internet-facing instances of pH7Builder below version 18.5.0 are currently at risk of exploitation.

## Recommendation

- Upgrade pH7 Social Dating CMS to version 18.5.0 or later immediately.
- Implement strict input validation on the picture_link parameter within the picture module to prevent path traversal sequences.
- Restrict file system permissions for the web server user to the minimum necessary directories to limit the scope of potential file deletions.
- Audit web server access logs for POST requests to the picture module containing directory traversal characters (e.g., "../" or "..\\").
