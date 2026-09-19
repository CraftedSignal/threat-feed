---
title: 'Stored XSS in Asset CleanUp: Page Speed Booster WordPress Plugin'
slug: 2026-09-asset-cleanup-xss
description: 'Asset CleanUp: Page Speed Booster versions 1.4.0.5 and earlier are vulnerable to stored cross-site scripting due to insufficient input sanitization of comment content.'
date: "2026-09-19T04:08:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:assetcleanup:page_speed_booster:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - 'Asset CleanUp: Page Speed Booster (<= 1.4.0.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this when the 'combine_loaded_css' setting is enabled to inject malicious scripts that execute in the context of a user's browser session.
    confidence_band: high
cves:
  - id: CVE-2026-13354
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13354
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security Team
  immediate_actions:
    - action: 'Upgrade Asset CleanUp: Page Speed Booster to version > 1.4.0.5'
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-13354 vulnerability patch requirement
  mitigation_plan:
    - priority: immediate
      action: Disable the combine_loaded_css setting in Asset CleanUp plugin
      owner: Web Security Team
      addresses: CVE-2026-13354
      evidence: NVD vulnerability details regarding exploit dependency
---

The Asset CleanUp: Page Speed Booster plugin for WordPress, specifically in versions 1.4.0.5 and earlier, contains a critical stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-13354. The vulnerability exists due to insufficient sanitization and output escaping when processing comment content. An unauthenticated attacker can leverage this flaw to inject arbitrary malicious web scripts into pages. These scripts are subsequently executed in the browser of any user who accesses the compromised page, potentially leading to unauthorized actions, session hijacking, or redirection. Successful exploitation is contingent on the site having the 'combine_loaded_css' configuration setting enabled. Given the nature of the vulnerability, it presents a high risk for sites that allow user comments and utilize this specific performance-enhancing plugin configuration.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of victim browsers. This can lead to the theft of session cookies, administrative account takeover, or redirection of users to malicious third-party websites. The vulnerability impacts all WordPress installations using the vulnerable plugin version with the specific CSS combination feature active.

## Recommendation

Prioritize the following actions to mitigate risk associated with CVE-2026-13354:
- Update the 'Asset CleanUp: Page Speed Booster' plugin to a version released after 1.4.0.5 immediately.
- Review WordPress site configurations and temporarily disable the 'combine_loaded_css' setting if immediate patching is not possible.
- Perform an audit of existing comments and site content for embedded script tags or suspicious attributes if the site has been exposed to the internet.
