---
title: Path Traversal Vulnerability in Piwigo Image Derivative Handler
slug: 2026-09-piwigo-path-traversal
description: Piwigo versions up to 16.3.0 contain a path traversal vulnerability in the i.php component, allowing remote unauthenticated attackers to access unauthorized files on the host system.
date: "2026-09-02T05:11:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:piwigo:piwigo:*:*:*:*:*:*:*:*
vendors:
  - Piwigo
products:
  - Piwigo (<= 16.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1006
    technique_name: Path Traversal
    evidence: The manipulation leads to path traversal.
    confidence_band: high
cves:
  - id: CVE-2026-84441
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84441
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Piwigo to version 16.3.1 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web access logs for sequences such as ../ or ..\ in requests targeting i.php
      technique_id: T1006
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source confirms path traversal vulnerability in i.php
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Piwigo 16.3.1 or later
      owner: IT Operations
      addresses: CVE-2026-84441
      evidence: Source vulnerability advisory
---

Piwigo versions up to and including 16.3.0 are vulnerable to a path traversal flaw residing within the Image Derivative Handler component, specifically within the i.php file. This vulnerability arises from improper input validation, allowing a remote, unauthenticated attacker to supply specially crafted input to manipulate file paths. By exploiting this flaw, an attacker can bypass intended access controls to read sensitive files or potentially interact with arbitrary files located on the underlying server filesystem. Given that the exploit code has been publicly disclosed, the barrier to entry for exploitation is low, and organizations running affected Piwigo installations should prioritize mitigation.

## Impact

Successful exploitation of this vulnerability allows unauthorized file access on the host server. This can lead to the exposure of sensitive configuration files, database credentials, or application source code, potentially resulting in complete system compromise depending on the server configuration and file permissions.

## Recommendation

Update all Piwigo installations to version 16.3.1 or later immediately. Ensure that the web server process runs with the least privilege necessary to limit the impact of potential path traversal attacks.
