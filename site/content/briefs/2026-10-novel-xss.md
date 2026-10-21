---
brief_id: brief-2026-10-21-novel-xss
event_id: brief-2026-10-21-novel-xss
revision: 1
activity_at: "2026-10-21T18:06:27Z"
title: 'Xxyopen Novel: DOM-based Cross-Site Scripting (CVE-2025-65442)'
slug: 2026-10-novel-xss
description: Xxyopen Novel version 3.5.0 contains a DOM-based Cross-Site Scripting vulnerability in its comment module, allowing attackers to execute arbitrary JavaScript in the context of other users' sessions.
date: "2026-10-21T18:06:27Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:xxyopen:novel:3.5.0:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - cwe-79
vendors:
  - Xxyopen
products:
  - Novel (3.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw lies in inadequate validation/encoding of user-submitted comment content... The platform retrieves unencoded comments... and renders the data directly into the DOM.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can submit malicious comments... and trigger code execution to steal session cookies.
    confidence_band: high
cves:
  - id: CVE-2025-65442
    cvss: 6.1
    epss: 0.00355
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZERO-DAY348-CVE-2025-65442-DOM-BASED-CROSS-SITE-SCRIPTING-XSS-VULNERABILITY-IN-NOVEL-V3.5.0-CWE-79-&utm_source=rss&utm_medium=rss
  - https://github.com/201206030/novel
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all instances of Xxyopen Novel version 3.5.0 in the environment.
      owner: IT Operations
      due: 24h
      evidence: Source identifies 3.5.0 as the affected version.
  hunt_leads:
    - lead: Search web access logs for requests to /api/book/comment/list?bookId= that include suspicious character patterns (e.g., <script, <svg, onload, onerror).
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploit involves submitting payloads into the comment module via API.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the book comment module if the application is not immediately patchable.
      owner: IT Operations
      addresses: CVE-2025-65442
      evidence: The comment module is the primary trigger point for the XSS.
---

CVE-2025-65442 is a DOM-based Cross-Site Scripting (XSS) vulnerability affecting Xxyopen Novel version 3.5.0. The vulnerability stems from inadequate sanitization of user-submitted book comments. Malicious payloads stored in the database are retrieved by the application via an API, cached in the victim's browser local storage, and subsequently rendered directly into the DOM using the Vue 3 'v-html' directive without filtering. Successful exploitation allows for session cookie theft and impersonation.

## Attack Chain

1. Attacker authenticates to the target Novel platform with a legitimate account.
2. Attacker navigates to the book detail page and identifies the comment submission module.
3. Attacker submits a comment containing a malicious XSS payload (e.g., `<svg onload=...>`).
4. The application stores the unencoded malicious payload in the 'book_comment' database table.
5. A victim user navigates to the affected book detail or comment list page.
6. The victim's browser fetches the comment list via the '/api/book/comment/list' endpoint.
7. The front-end client stores the malicious content into 'window.localStorage' using the key 'book_comment_{bookId}'.
8. The Vue 3 application renders the stored content directly into the DOM via 'v-html', triggering the execution of the injected script in the victim's browser session.

## Impact

Successful exploitation leads to unauthorized code execution within the victim's browser context. This allows attackers to potentially steal session cookies, perform actions on behalf of the victim, or tamper with the rendered content of the page.

## Recommendation

1. Upgrade Xxyopen Novel to a patched version once available from the vendor; currently, version 3.5.0 is the only confirmed affected version.
2. Implement strict output encoding and sanitization for all user-contributed content before rendering, specifically within Vue 3 components that utilize the 'v-html' directive.
3. Review and secure the API endpoints handling comment retrieval to ensure consistent server-side input validation and output encoding.
4. Inspect application logs for anomalous requests to the '/api/book/comment/list' endpoint containing common XSS vectors or suspicious HTML tags.
