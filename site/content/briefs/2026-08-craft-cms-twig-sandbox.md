---
title: Craft CMS Authenticated RCE via Twig Sandbox Escape
slug: 2026-08-craft-cms-twig-sandbox
description: An authenticated remote code execution vulnerability exists in Craft CMS due to an overly permissive Twig sandbox policy that exposes dangerous Yii framework components.
date: "2026-08-06T21:29:17Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Craft CMS
products:
  - Craft CMS 5.x
  - Craft CMS 4.x
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows sandboxed Twig templates to use known payloads based on the function-call gadget to achieve RCE.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f5wm-88jv-g5hx
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all instances of Craft CMS to versions 5.10.7 or 4.18.3.
      owner: IT Operations
      due: 48h
      evidence: Affected packages list in source.
---

Craft CMS versions prior to 5.10.7 and 4.18.3 contain a vulnerability in their Twig template sandbox implementation. The sandbox uses a `SecurityPolicy` class that determines which methods and properties are accessible within user-defined templates. The vulnerability arises because the sandbox policy allows access to classes based on inheritance hierarchies. Specifically, the `ElementInterface`, which is marked as safe for the sandbox, is inherited by objects that eventually lead to the `yii\base\Component` class from the underlying Yii framework. 

This framework class contains known gadgets that can be used to execute arbitrary functions. Because the sandbox policy does not properly restrict access to methods inherited from parent classes, an authenticated attacker who can modify or create Twig templates within the control panel can trigger these dangerous methods to achieve remote code execution (RCE). This issue represents a regression of previous security bypasses in the Craft CMS sandbox mechanism.

## Impact

Successful exploitation allows an authenticated user with access to the control panel to execute arbitrary system code. This grants the attacker full control over the application environment. Given the high degree of access required, the vulnerability poses a significant risk to organizations managing content through the Craft CMS administrative interface.

## Recommendation

- Upgrade Craft CMS installations to version 5.10.7 or 4.18.3 or higher to apply the security patch for the Twig sandbox.
- Audit permissions within the Craft CMS control panel to ensure that only trusted users have the ability to modify or save Twig templates.
- Review custom code that utilizes `AllowedInSandbox` attributes or custom class allowlists for potential exposure of underlying framework components.
