---
title: MantisBT Stored XSS Vulnerability in Saved-Filter Owner Column (CVE-2026-40607)
slug: 2026-05-mantisbt-xss
description: MantisBT versions 2.1.0 through 2.28.1 are vulnerable to stored cross-site scripting (XSS) due to improper escaping of the saved-filter owner field, allowing attackers with Manager access or higher to inject arbitrary HTML when the `$g_show_user_realname` configuration option is enabled.
date: "2026-05-11T19:38:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - stored-xss
  - mantisbt
  - cve-2026-40607
vendors:
  - composer
  - MantisBT
products:
  - mantisbt/mantisbt (>= 2.1.0, <= 2.28.1)
references:
  - https://github.com/advisories/GHSA-f633-865q-2mhh
  - CVE-2026-40607
rules:
  - title: Detect MantisBT Stored XSS Attempt
    description: Detects CVE-2026-40607 exploitation — Detects creation of a saved filter containing potentially malicious JavaScript code in the owner realname.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect MantisBT show_user_realname Configuration
    description: Detects attempts to set the `$g_show_user_realname` setting to 'ON' or similar values that might expose real names and trigger XSS.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
rules_count: 2
---

MantisBT versions 2.1.0 to 2.28.1 are susceptible to a stored cross-site scripting (XSS) vulnerability (CVE-2026-40607) within the saved filter functionality. This vulnerability arises from the improper sanitization of the filter owner's name when `$g_show_user_realname` is enabled, which leads to arbitrary HTML injection. By default, only users with Manager access level or above can save filters publicly, making them the primary targets or vectors for exploitation. Successful exploitation allows attackers to execute malicious JavaScript code within the context of other users' sessions, potentially leading to session hijacking, defacement, or sensitive information disclosure. The vulnerability was discovered and reported by siunam (Tang Cheuk Hei).

## Attack Chain

1. An attacker with Manager or Administrator privileges logs into a vulnerable MantisBT instance.
2. The attacker creates a new saved filter.
3. In the filter creation process, the attacker crafts a malicious payload containing JavaScript code within their user realname field in their profile settings.
4. The attacker saves the filter, which stores the malicious payload in the database due to insufficient output escaping.
5. Another user with access to the saved filter views the list of saved filters.
6. The MantisBT application retrieves the saved filter data from the database, including the attacker's crafted payload within the owner's real name.
7. Because `$g_show_user_realname` is enabled, the application displays the filter owner's real name without proper sanitization, executing the malicious JavaScript code in the victim's browser.
8. The attacker successfully executes arbitrary JavaScript code in the victim's session, potentially stealing cookies, redirecting to malicious sites, or performing other unauthorized actions.

## Impact

Successful exploitation of this XSS vulnerability could lead to account compromise, sensitive data leakage, and website defacement. Since the vulnerability requires Manager or Admin access to create a malicious filter, it could lead to privilege escalation if an attacker compromises a Manager account. The number of potential victims depends on the MantisBT instance's user base. Organizations using vulnerable versions of MantisBT for bug tracking and project management are at risk.

## Recommendation

*   Upgrade MantisBT to a patched version beyond 2.28.1 to remediate CVE-2026-40607.
*   As a workaround, disable the display of users' real names by setting `$g_show_user_realname = OFF;` in the MantisBT configuration to prevent the XSS payload from rendering.
*   Restrict the ability to store filters by setting `$g_stored_query_create_threshold` and `$g_stored_query_create_shared_threshold` to `NOBODY` to prevent unauthorized users from creating malicious filters.
*   Deploy the Sigma rule "Detect MantisBT Stored XSS Attempt" to identify potential exploitation attempts through filter creation containing suspicious JavaScript code.
