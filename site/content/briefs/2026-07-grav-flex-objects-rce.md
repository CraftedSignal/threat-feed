---
title: Grav Flex Objects Plugin Stored Template Injection Leading to RCE
slug: 2026-07-grav-flex-objects-rce
description: A stored server-side template injection vulnerability, identified as CVE-2026-58655, exists in the Grav Flex Objects plugin before version 1.4.0, allowing an attacker to achieve arbitrary Twig execution and remote command execution by injecting malicious code into user-controlled title frontmatter that bypasses sanitization.
date: "2026-07-15T12:25:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - template-injection
  - rce
  - web-vulnerability
  - cms
  - grav
  - php
vendors:
  - Grav
products:
  - Grav Flex Objects plugin < 1.4.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who can control the title frontmatter... can achieve arbitrary Twig execution and escalate to remote command execution via access to internal Grav services such as the scheduler.
    confidence_band: high
cves:
  - id: CVE-2026-58655
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58655
rules:
  - title: Detects CVE-2026-58655 Exploitation - Grav Flex Objects SSTI
    description: Detects exploitation attempts of CVE-2026-58655, a stored server-side template injection vulnerability in Grav Flex Objects plugin, by identifying suspicious Twig template syntax targeting title frontmatter in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.008
    data_sources:
      - webserver
rules_count: 1
---

A critical stored server-side template injection vulnerability, CVE-2026-58655, affects the bundled Grav Flex Objects plugin (getgrav/grav-plugin-flex-objects) in versions prior to 1.4.0. This flaw allows an attacker to inject and execute arbitrary Twig code by manipulating the `page.header.flex.collection.title` or `page.header.flex.object.title` frontmatter values. The plugin's `template_from_string()` function insecurely processes these user-controlled inputs as executable Twig code during dynamic collection or object title rendering, effectively bypassing Grav's `Security::cleanDangerousTwig()` sanitization. Successful exploitation grants an unauthenticated attacker remote command execution capabilities on the vulnerable Grav instance, potentially through access to internal Grav services like the scheduler. This could lead to full system compromise and data exfiltration.

## Attack Chain

1. An attacker identifies a publicly accessible Grav Flex Objects page.
2. The attacker crafts malicious Twig template code designed to achieve arbitrary command execution, possibly leveraging internal Grav services like the scheduler.
3. The attacker injects this malicious Twig code into the `title` frontmatter (e.g., `page.header.flex.collection.title` or `page.header.flex.object.title`) of the target Flex Objects page.
4. The Grav Flex Objects plugin receives and stores the maliciously crafted frontmatter.
5. When the affected page's title is dynamically rendered, the plugin's `template_from_string()` function attempts to process the user-controlled frontmatter.
6. The `template_from_string()` function evaluates the injected malicious string as Twig code due to the vulnerability, bypassing security sanitization.
7. The embedded Twig code executes on the server, leading to arbitrary code execution and potential escalation to remote command execution.
8. The attacker's commands are executed on the host system, enabling full compromise or data exfiltration.

## Impact

Successful exploitation of CVE-2026-58655 results in remote code execution (RCE) on the compromised Grav instance. An attacker can gain full control over the affected web server, including the ability to install backdoors, steal sensitive data, modify website content, or use the server as a platform for further attacks. This vulnerability poses a severe risk to the integrity and confidentiality of the Grav installation and any data it manages. While specific victim counts are not available, all Grav installations using the Flex Objects plugin prior to version 1.4.0 are at risk.

## Recommendation

* Upgrade the Grav Flex Objects plugin to version 1.4.0 or newer immediately to patch CVE-2026-58655.
* Deploy the provided Sigma rule to your SIEM to detect attempts at server-side template injection via suspicious Twig syntax in web requests.
* Enable comprehensive web server logging, including full URI query strings and POST body parameters, to capture evidence for the detection rule.
