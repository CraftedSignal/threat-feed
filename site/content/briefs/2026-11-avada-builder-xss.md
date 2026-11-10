---
brief_id: brief-2026-11-10-avada-builder-xss
event_id: brief-2026-11-10-avada-builder-xss
revision: 1
activity_at: "2026-11-10T10:06:04Z"
title: 'Avada (Fusion) Builder: Stored Cross-Site Scripting (CVE-2026-84938)'
slug: 2026-11-avada-builder-xss
description: The Avada (Fusion) Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting due to insufficient input sanitization in Form Notification dynamic data handling, allowing unauthenticated attackers to execute arbitrary scripts when victims view rendered Post Card elements.
date: "2026-11-10T10:06:04Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:themefusion:avada_builder:*:*:*:*:*:wordpress:*:*
vendors:
  - ThemeFusion
products:
  - Avada (Fusion) Builder (<= 3.16.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Exploitation allows for arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-84938
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84938
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Avada (Fusion) Builder to the latest version beyond 3.16.1.
      owner: IT Operations
      due: 48h
      evidence: Plugin is vulnerable in all versions up to, and including, 3.16.1.
  hunt_leads:
    - lead: Identify WordPress pages using Fusion Builder elements with Dynamic Data sources.
      technique_id: T1190
      data_needed:
        - WordPress database entries for wp_postmeta or plugin-specific metadata tables
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires that a Fusion Form is embedded on an admin-authored page and a Post Cards element configured to display attachment post types is present.
  mitigation_plan:
    - priority: immediate
      action: Update the Avada (Fusion) Builder plugin to version > 3.16.1.
      owner: IT Operations
      addresses: CVE-2026-84938
      evidence: Plugin versions <= 3.16.1 are vulnerable.
---

The Avada (Fusion) Builder plugin for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-84938) affecting versions 3.16.1 and earlier. The flaw arises from inadequate input sanitization and output escaping within the Form Notification Dynamic-Data functionality. An unauthenticated attacker can leverage this to inject malicious web scripts that execute within the context of a user session when viewing pages containing affected Post Cards elements.

## Impact

Successful exploitation results in arbitrary script execution in the browser of users viewing pages where the malicious payload is rendered. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or defacement. Exploitation requires specific site configurations: the target must have a Fusion Form embedded on an admin-authored page and a Post Cards element configured to display attachment post types on a publicly accessible page.

## Recommendation

* Update the Avada (Fusion) Builder plugin to a version beyond 3.16.1 immediately to resolve the sanitization and escaping issues.
* Review WordPress site configurations to identify pages using the Fusion Form notification dynamic data hook combined with Post Cards elements.
* Monitor WordPress web access logs for unusual POST requests targeting form notification handling endpoints, specifically looking for injection attempts in payload parameters.
