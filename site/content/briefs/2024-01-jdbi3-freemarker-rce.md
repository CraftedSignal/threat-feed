---
title: JDBI Freemarker Template Engine Vulnerability Leads to Remote Code Execution
slug: 2024-01-jdbi3-freemarker-rce
description: Jdbi's freemarker module is vulnerable to arbitrary command execution when an application permits attacker-influenced text to reach FreemarkerEngine.parse() as template source, affecting org.jdbi:jdbi3-freemarker through version 3.52.1 and potentially leading to RCE.
date: "2026-05-05T22:15:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freemarker
  - template-injection
  - rce
  - jdbi
vendors:
  - H2 Database
  - JDBI
products:
  - jdbi3-freemarker (<= 3.52.1)
  - h2 (2.2.224)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
references:
  - https://github.com/advisories/GHSA-mggx-p7jf-jgw4
rules:
  - title: Detect JDBI Freemarker RCE Attempt via Execute Class
    description: Detects attempts to exploit the JDBI Freemarker RCE vulnerability by looking for the instantiation of the Execute class within FreeMarker templates.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1205
    data_sources:
      - process_creation
      - linux
  - title: Detect JDBI Freemarker RCE Attempt via touch command
    description: Detects attempts to exploit the JDBI Freemarker RCE vulnerability by looking for the touch command within FreeMarker templates.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1205
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The jdbi3-freemarker library, when used with attacker-controlled template source, is vulnerable to remote code execution (RCE). This vulnerability stems from the improper neutralization of special elements used in the FreeMarker template engine. Specifically, the library's default configuration does not restrict Java class instantiation within FreeMarker templates, allowing attackers to instantiate arbitrary classes, including those that can execute system commands. The vulnerability affects jdbi3-freemarker versions up to and including 3.52.1. Successful exploitation requires an application to depend on the vulnerable library and permit attacker-influenced text to be used as a SQL template, either directly or indirectly through template evaluation.

## Attack Chain

1. An attacker identifies an application using jdbi3-freemarker for SQL templating.
2. The attacker discovers an endpoint where user-supplied input is incorporated into a SQL query.
3. The attacker crafts a malicious FreeMarker template payload containing a Java class instantiation that executes arbitrary commands (e.g., `${"freemarker.template.utility.Execute"?new()("touch /tmp/jdbi-pwned")}`).
4. The attacker injects the malicious payload into the application's vulnerable endpoint.
5. The application processes the attacker's input as a FreeMarker template using `FreemarkerEngine.parse()`.
6. Due to the lack of a `TemplateClassResolver`, FreeMarker's legacy `UNRESTRICTED_RESOLVER` is active, allowing the instantiation of the `freemarker.template.utility.Execute` class.
7. The `Execute` class executes the attacker's command, creating the `/tmp/jdbi-pwned` file on the server.
8. The attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code within the application's JVM. This can lead to complete compromise of the affected system, including data theft, system modification, and denial of service. The vulnerability impacts all jdbi3-freemarker releases through version 3.52.1. Applications relying on jdbi3-freemarker and dynamically constructing SQL queries with user-controlled data are at high risk.

## Recommendation

*   Upgrade to a version of `org.jdbi:jdbi3-freemarker` that includes the fix described in GHSA-mggx-p7jf-jgw4 (versions > 3.52.1).
*   Apply the proposed patch in `FreemarkerConfig.java` and `FreemarkerSqlLocator.java` by setting `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` to prevent arbitrary Java class instantiation by default.
*   Deploy the provided Sigma rules to your SIEM to detect potential exploitation attempts targeting this vulnerability.
*   Sanitize user-provided input before incorporating it into SQL queries to prevent injection attacks.
*   If dynamic SQL templating is required, review and restrict the classes that can be instantiated within FreeMarker templates.
