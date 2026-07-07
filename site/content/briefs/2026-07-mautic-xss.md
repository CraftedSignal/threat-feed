---
title: Mautic Stored XSS in Projects Component (CVE-2026-9809)
slug: 2026-07-mautic-xss
description: A high-severity stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-9809, affects Mautic 7's Projects component, allowing an authenticated user with project creation/edit permissions to inject malicious script payloads into project names that execute when an administrative user hovers over affected project tags, potentially leading to administrative actions, configuration alteration, or sensitive data exfiltration.
date: "2026-07-03T11:32:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - mautic
  - cve
vendors:
  - Mautic
products:
  - Mautic 7
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When an administrative user views an entity associated with a compromised project and hovers over its tag, the injected script executes within the context of their active browser session.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: A stored Cross-Site Scripting (XSS) vulnerability exists in the Projects component of Mautic 7... An authenticated user with permissions to create or edit projects can exploit this to inject malicious script payloads.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated user with permissions to create or edit projects can exploit this to inject malicious script payloads.
    confidence_band: high
cves:
  - id: CVE-2026-9809
    cvss: 7.6
    epss: 0.00164
references:
  - https://github.com/advisories/GHSA-7h65-whp7-rgqf
---

A significant stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-9809) has been discovered in the Projects component of Mautic version 7. This flaw permits an authenticated attacker with permissions to create or edit projects to inject arbitrary malicious JavaScript into project names. When these unsanitized project names are subsequently rendered in administrative detail views (such as campaigns or forms) and an administrative user hovers over the associated project tag or popover, the injected script executes within the victim's browser context. This could lead to session hijacking, unauthorized administrative actions, modification of system configurations, or exfiltration of sensitive organizational data. The vulnerability specifically affects Mautic versions 7.0.0 through 7.1.1 and has been addressed in version 7.1.2. Mautic 6.x, 5.x, and 4.x branches are not impacted as they do not include the Projects feature.

## Attack Chain

1.  An attacker gains legitimate, authenticated access to a Mautic 7 instance with permissions to create or modify projects.
2.  Using the Mautic administrative interface, the attacker navigates to the project creation or editing functionality.
3.  The attacker creates a new project or modifies an existing one, injecting a malicious script payload (e.g., `<script>alert(document.domain)</script>`) into the project name field.
4.  Mautic stores this unsanitized project name, including the malicious script, in its backend database.
5.  A victim administrative user accesses an administrative detail view (e.g., a campaign or email detail page) that displays entities associated with the compromised project.
6.  As the victim user hovers their mouse cursor over the malicious project's tag or a related popover on the administrative detail page, the unsanitized project name is rendered client-side.
7.  The malicious JavaScript code, embedded within the project name, executes within the victim's web browser in the context of their Mautic session.
8.  The executed script hijacks the victim's session, exfiltrates sensitive information, performs unauthorized administrative actions, or alters system configurations on behalf of the victim.

## Impact

Successful exploitation of CVE-2026-9809 grants attackers the ability to execute arbitrary JavaScript code within the context of an unsuspecting administrative user's Mautic session. This direct access to the victim's browser session allows for significant consequences including, but not limited to, session hijacking, exfiltration of sensitive data, unauthorized modification of Mautic's system configurations, or even complete administrative control over the Mautic instance. While no specific victim counts or sectors are detailed, any organization utilizing Mautic 7 (versions 7.0.0 to 7.1.1) for marketing automation is vulnerable to these severe data integrity and confidentiality risks if an authenticated user with project management permissions is compromised or malicious.

## Recommendation

*   **Patch CVE-2026-9809** by upgrading all Mautic 7 installations to version 7.1.2 or later immediately.
*   Restrict project creation and modification permissions to only highly trusted administrative users within your Mautic instance to mitigate the risk until patching is complete.
