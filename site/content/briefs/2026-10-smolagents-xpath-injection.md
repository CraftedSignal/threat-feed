---
brief_id: brief-2026-10-21-smolagents-xpath-injection
event_id: brief-2026-10-21-smolagents-xpath-injection
revision: 1
activity_at: "2026-10-21T04:16:21Z"
title: 'Hugging Face smolagents: XPath injection in vision_web_browser.py (CVE-2025-11844)'
slug: 2026-10-smolagents-xpath-injection
description: An XPath injection vulnerability in the Hugging Face smolagents library (CVE-2025-11844) allows for local data extraction and arbitrary DOM traversal via improper input validation in the search_item_ctrl_f function.
date: "2026-10-21T04:16:21Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; vulnerability details regarding function and path confirmed.
cpes:
  - cpe:2.3:a:huggingface:smolagents:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - xpath-injection
  - ai-security
vendors:
  - Hugging Face
products:
  - smolagents (< 1.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The target framework uses an un-sanitized string directly inside an internal XPath querying function.
    confidence_band: high
cves:
  - id: CVE-2025-11844
    cvss: 5.4
    epss: 0.00283
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SPARSHBISWAS-AI-CVE-2025-11844-SMOLAGENTS
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade smolagents to 1.22.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2025-11844 patch availability.
  mitigation_plan:
    - priority: short_term
      action: Implement input validation for inputs passed to search_item_ctrl_f
      owner: Application Security
      addresses: CVE-2025-11844
      evidence: Source details on improper input validation.
---

CVE-2025-11844 is an XPath injection vulnerability affecting the Hugging Face smolagents library in versions prior to 1.22.0. The vulnerability resides within the `search_item_ctrl_f` function located in `vision_web_browser.py`. This issue occurs because user-supplied input is directly concatenated into an internal XPath query string - specifically formatted as `//*[contains(text(), 'USER_INPUT_HERE')]` - without sufficient sanitization or validation. By crafting malicious input, an attacker can escape the intended query structure, facilitating arbitrary DOM traversal and potential information disclosure within environments utilizing the library for vision-based web browsing tasks. The availability of proof-of-concept scanning frameworks elevates the risk for organizations relying on this library for automated agentic workflows.

## Attack Chain

1. The attacker identifies an application or agent workflow utilizing a vulnerable version of the `smolagents` library.
2. The attacker triggers a function call that eventually invokes `search_item_ctrl_f` in `vision_web_browser.py`.
3. The attacker provides a specifically crafted malicious string as input to the affected function parameter.
4. The application logic concatenates the malicious input directly into an XPath query string.
5. The XPath engine executes the modified query, allowing the attacker to break out of the intended query context.
6. The attacker performs arbitrary DOM traversal to extract sensitive data or bypass intended input restrictions.

## Impact

Successful exploitation can lead to local data extraction and information disclosure. The vulnerability affects users and automated agents using the smolagents library for vision-based web interaction. While the CVSS score is 5.4, the potential for unauthorized access to data processed or retrieved by AI agents presents a significant risk to the integrity of agent-driven automation workflows.

## Recommendation

* Update the `smolagents` library to version 1.22.0 or later to patch the input validation flaw associated with CVE-2025-11844.
* Review applications utilizing `smolagents` to identify if any user-controlled input is passed directly to the `search_item_ctrl_f` function.
* Implement strict input validation and sanitization for all strings processed by the library in custom agent implementations until the library is patched.
