---
brief_id: brief-2026-10-26-godot-arbitrary-code-execution
event_id: brief-2026-10-26-godot-arbitrary-code-execution
revision: 1
activity_at: "2026-10-26T22:34:54Z"
title: 'Godot Engine: Arbitrary code execution via .po translation file'
slug: 2026-10-godot-arbitrary-code-execution
description: A vulnerability in the Godot 4.x .po translation file loader allows for arbitrary code execution due to improper validation of the Plural-Forms header during plural lookup operations.
date: "2026-10-26T22:34:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; needs security update release for final remediation
tags:
  - code-execution
  - translation
  - godot
  - vulnerability
vendors:
  - Godot Engine
products:
  - Godot Engine (4.1.0 through 4.7.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The .po loader stores the file's Plural-Forms header without validating it against the GNU gettext grammar (core/io/translation_loader_po.cpp:232). At the first plural lookup the header is...
    confidence_band: high
references:
  - https://seclists.org/oss-sec/2026/q4/396
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory applications using Godot 4.1.0-4.7.2
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Godot 4.1.0 through 4.7.2
  hunt_leads:
    - lead: Identify applications loading external or non-signed .po files
      technique_id: T1059
      data_needed:
        - File system access logs for .po file reads
        - Application integrity monitoring
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is triggered by the .po loader during plural lookup
  mitigation_plan:
    - priority: immediate
      action: Apply future security patches for Godot 4.x as released by the maintainers
      owner: IT Operations
      addresses: Godot Engine 4.1.0 through 4.7.2
      evidence: Affected versions identified in disclosure
---

A code-execution vulnerability has been identified in Godot 4.x versions 4.1.0 through 4.7.2. The vulnerability exists within the translation loading component, specifically in the parsing logic for .po (Portable Object) files. The engine fails to validate the 'Plural-Forms' header against the GNU gettext grammar within `core/io/translation_loader_po.cpp`. Exploitation occurs during the first plural lookup, where a maliciously crafted header can lead to code execution. This vulnerability is not present in Godot 3.5.

## Impact
Successful exploitation allows for arbitrary code execution within the context of the running Godot application.

## Recommendation
- Inventory all projects utilizing Godot Engine 4.1.0 through 4.7.2.
- Implement strict input validation for all external translation files (.po) loaded by the engine until a security update is applied.
- Monitor for and apply upcoming patches from the Godot Engine developers for the affected 4.x versions.
