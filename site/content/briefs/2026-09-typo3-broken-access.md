---
title: Broken Access Control in TYPO3 CMS Backend and Install Tool
slug: 2026-09-typo3-broken-access
description: TYPO3 CMS versions 13.0.0 through 13.4.33 and 14.0.0 through 14.3.5 contain a broken access control vulnerability (CVE-2026-19418) that allows attackers to perform unauthorized actions by abusing ineffective referrer enforcement.
date: "2026-09-02T00:00:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-application
  - cms
  - vulnerability
  - cve-2026-19418
vendors:
  - TYPO3
products:
  - TYPO3 CMS (13.0.0 - 13.4.33)
  - TYPO3 CMS (14.0.0 - 14.3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers able to execute JavaScript on one of those domains, for instance by exploiting a cross-site scripting vulnerability, could invoke these endpoints via Fetch/XHR with the privileges of an authenticated victim's user session.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Attackers able to execute JavaScript on one of those domains, for instance by exploiting a cross-site scripting vulnerability, could invoke these endpoints via Fetch/XHR with the privileges of an authenticated victim's user session.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-68jx-f42c-7599
  - https://www.cve.org/CVERecord?id=CVE-2026-19418
  - https://news.typo3.com/security/advisory/typo3-core-sa-2020-006
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all TYPO3 CMS instances to the patched versions (13.4.34 LTS or 14.3.6 LTS).
      owner: IT Operations
      due: 24h
      evidence: Solution section specifies these versions fix the problem.
  mitigation_plan:
    - priority: immediate
      action: Review and deploy strict Content Security Policy headers to mitigate potential XSS vectors.
      owner: Security Engineering
      addresses: CVE-2026-19418
      evidence: XSS is required to trigger this access control bypass.
---

TYPO3 CMS is vulnerable to a broken access control flaw identified as CVE-2026-19418, affecting versions 13.0.0 through 13.4.33 and 14.0.0 through 14.3.5. This issue stems from a regression introduced when TYPO3 v13.0 transitioned to serving backend and Install Tool applications from the site root entry script rather than a dedicated directory. The application relies on referrer validation to verify the origin of administrative requests. Because the site root is now the origin for both frontend and backend requests, the validation logic fails to distinguish between them. An attacker capable of executing arbitrary JavaScript on a frontend domain, such as through a Cross-Site Scripting (XSS) vulnerability, can craft Fetch or XHR requests that bypass these origin checks. Consequently, the attacker can invoke sensitive backend or Install Tool endpoints using the session privileges of an authenticated administrator, leading to potential site takeover or configuration modification.

## Impact

Successful exploitation allows an unauthenticated attacker to abuse an authenticated administrator's session to execute privileged administrative operations. This can lead to unauthorized changes to the TYPO3 instance configuration, modification of content, or full administrative takeover of the CMS, depending on the available functions within the backend and Install Tool.

## Recommendation

* Immediately upgrade TYPO3 installations to version 13.4.34 LTS or 14.3.6 LTS to resolve CVE-2026-19418.
* Audit all public-facing pages for potential Cross-Site Scripting (XSS) vulnerabilities, as these serve as the primary delivery vector for this access control bypass.
* Implement strict Content Security Policy (CSP) headers to restrict where the browser can load resources and where it can send asynchronous requests, mitigating the risk of unauthorized XHR/Fetch invocations.
