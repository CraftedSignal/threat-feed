---
title: OpenRemote IoT Platform Expression Injection Vulnerability
slug: 2024-01-09-openremote-injection
description: The OpenRemote IoT platform is vulnerable to expression injection, allowing remote code execution due to an unsandboxed Nashorn JavaScript engine and an inactive Groovy sandbox, leading to full server compromise.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openremote
  - expression-injection
  - remote-code-execution
  - iot
vendors:
  - OpenRemote
products:
  - OpenRemote IoT Platform
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-7mqr-33rv-p3mp
rules:
  - title: Detect OpenRemote JavaScript Ruleset Creation
    description: Detects the creation of JavaScript rulesets in OpenRemote, which can be indicative of expression injection attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - webserver
      - linux
  - title: Detect OpenRemote Groovy Ruleset Creation (Superuser Only)
    description: Detects the creation of Groovy rulesets in OpenRemote, which should only be allowed by superusers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The OpenRemote IoT platform contains critical expression injection vulnerabilities within its rules engine. The most significant of these vulnerabilities lies in the platform's use of the Nashorn JavaScript engine without proper sandboxing. This allows attackers with the `write:rules` role to inject malicious JavaScript code into rulesets, leading to arbitrary code execution on the server. The Groovy sandbox, intended as a security measure for Groovy rules, is rendered ineffective because the registration code is commented out. This lack of sandboxing, coupled with the ability of non-superusers to create JavaScript rulesets, creates a significant attack vector that can result in full server compromise. This vulnerability impacts all versions of the OpenRemote IoT platform prior to a patch.

## Attack Chain

1. An attacker crafts a malicious JavaScript payload designed to execute arbitrary code on the server, leveraging the `java.lang.Runtime` class.
2. The attacker authenticates to the OpenRemote platform with a user account that has the `write:rules` role.
3. The attacker sends an HTTP POST request to `/api/{realm}/rules/realm` with a JSON payload containing the malicious JavaScript code within the `rules` field and setting `lang` to `JAVASCRIPT`.
4. The `RulesResourceImpl.createRealmRuleset()` method receives the request and, due to the lack of validation for JavaScript rules, bypasses the intended Groovy-only restriction.
5. The malicious JavaScript code is then passed to the `RulesetStorageService.merge()` method and persisted in the `REALM_RULESET` table.
6. A Hibernate event listener is triggered, publishing a persistence event to a Camel SEDA topic.
7. The `RulesService` consumes this event and deploys the ruleset, triggering the execution of the attacker-controlled JavaScript code via `scriptEngine.eval(script, engineScope)` in `RulesetDeployment.java` L368.
8. The attacker achieves arbitrary code execution on the server, potentially leading to full server compromise, data exfiltration, or other malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the OpenRemote server. This can lead to full system compromise, including the ability to steal sensitive data, modify system configurations, or use the compromised server as a launchpad for further attacks. The lack of authentication requirements beyond the `write:rules` role significantly increases the risk of exploitation. Given the platform's use in IoT environments, the impact could extend to control over physical devices and infrastructure managed by the OpenRemote platform.

## Recommendation

*   Apply the patch provided by OpenRemote immediately to address the expression injection vulnerabilities (reference: [https://github.com/advisories/GHSA-7mqr-33rv-p3mp](https://github.com/advisories/GHSA-7mqr-33rv-p3mp)).
*   Monitor web server logs for POST requests to `/api/{realm}/rules/realm` containing `lang: "JAVASCRIPT"` in the request body, and investigate any suspicious activity (reference: webserver log monitoring).
*   Deploy the Sigma rule provided to detect the creation of JavaScript rulesets, and tune for your environment.
*   Implement strict input validation and output encoding for all user-supplied data to prevent expression injection attacks.
