---
title: Reflected XSS Vulnerability in ThemeGrill eStore Plugin
slug: 2026-10-estore-xss
description: The ThemeGrill eStore WordPress plugin contains a reflected cross-site scripting vulnerability (CVE-2026-108485) that allows attackers to execute arbitrary scripts in a user's browser session.
date: "2026-10-18T11:53:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themegrill:estore:*:*:*:*:*:wordpress:*:*
vendors:
  - ThemeGrill
products:
  - eStore (n/a - 1.6.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The eStore plugin contains a reflected cross-site scripting (XSS) vulnerability due to improper neutralization of input.
    confidence_band: high
cves:
  - id: CVE-2026-108485
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108485
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade eStore plugin to version 1.6.14 or latest available
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-108485 affects versions through 1.6.13
  mitigation_plan:
    - priority: immediate
      action: Enable WAF rules to detect and block XSS patterns in URI parameters
      owner: SOC
      addresses: CVE-2026-108485
      evidence: NVD vulnerability type indicates XSS
---

The eStore plugin by ThemeGrill is vulnerable to a reflected cross-site scripting (XSS) flaw, identified as CVE-2026-108485. This vulnerability exists due to the improper neutralization of user-supplied input during the web page generation process. Attackers can leverage this flaw by tricking an authenticated or unauthenticated user into clicking a malicious link that includes a crafted script. When the application reflects this input back to the user's browser without adequate sanitization, the script executes within the victim's session context. This vulnerability affects all eStore versions from inception through 1.6.13 and may result in session hijacking, unauthorized actions performed on behalf of the user, or the redirection of visitors to malicious websites.

## Impact

Successful exploitation of this reflected XSS vulnerability can lead to full compromise of a user's session within the WordPress environment. Depending on the privileges of the victim, an attacker could potentially modify site content, elevate privileges, or exfiltrate sensitive data. All organizations utilizing the ThemeGrill eStore plugin within the version range of n/a through 1.6.13 are at risk.

## Recommendation

Prioritize the update of the ThemeGrill eStore plugin to the latest available version that resolves CVE-2026-108485. Security teams should audit web server logs for suspicious URL parameters containing encoded scripts or unusual characters often associated with XSS payloads, specifically targeting requests directed toward the eStore plugin endpoints. Ensure that a robust Web Application Firewall (WAF) is configured to detect and block common XSS patterns in URI parameters.
