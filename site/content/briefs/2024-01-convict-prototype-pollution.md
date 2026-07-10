---
title: Convict NPM Package Prototype Pollution Vulnerability
slug: 2024-01-convict-prototype-pollution
description: The `convict` npm package is vulnerable to prototype pollution via the `load()`, `loadFile()`, and schema initialization functions, allowing attackers to overwrite properties on `Object.prototype` by supplying malicious input, potentially leading to unexpected behavior, authentication bypass, or remote code execution, affecting versions 6.2.4 and earlier.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prototype-pollution
  - npm
  - convict
vendors:
  - Mozilla
products:
  - convict
references:
  - https://github.com/advisories/GHSA-hf2r-9gf9-rwch
  - https://github.com/mozilla/node-convict/security/advisories/GHSA-44fc-8fm5-q62h
  - https://github.com/mozilla/node-convict/issues/423
rules:
  - title: Detect Prototype Pollution via Config File Upload
    description: Detects attempts to exploit prototype pollution vulnerabilities by identifying configuration file uploads containing `__proto__` or `constructor.prototype` in web server logs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Prototype Pollution Attempt via process arguments
    description: Detects possible prototype pollution attempts based on process arguments.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `convict` npm package, versions 6.2.4 and earlier, contains a prototype pollution vulnerability that can be exploited through multiple attack vectors. Two primary paths have been identified: configuration loading via `config.load()` or `config.loadFile()`, where recursive merging of configuration data fails to sanitize input keys, and schema initialization, where crafting a schema with malicious `constructor.prototype.*` keys allows for direct writes to `Object.prototype` during application startup. Successful exploitation allows attackers to inject or modify properties on the `Object.prototype`, potentially leading to critical consequences such as authentication bypass or remote code execution. This vulnerability arises from insufficient input validation when processing configuration data. Defenders need to ensure that they are not passing untrusted data into `convict`'s `load`, `loadFile` or schema initialization methods.

## Attack Chain

1. An attacker identifies a vulnerable application using the `convict` npm package version 6.2.4 or earlier.
2. The attacker crafts a malicious JSON configuration file containing `__proto__` or `constructor.prototype` keys with attacker-controlled values.
3. The attacker injects this malicious JSON data into the application, potentially through a file upload, API endpoint, or other data input mechanisms.
4. The application calls `config.load()` or `config.loadFile()` with the attacker-controlled JSON data.
5. The `overlay()` function recursively merges the attacker-provided data with the existing configuration.
6. Due to the lack of input validation, the recursion reaches `Object.prototype`.
7. The attacker's malicious values are written to `Object.prototype`, polluting the prototype.
8. Depending on how the polluted properties are consumed by the application, this can lead to unexpected behavior, authentication bypass, or remote code execution.

## Impact

Successful exploitation of this vulnerability allows attackers to inject or modify properties on the `Object.prototype`, potentially leading to unexpected behavior, authentication bypass, or remote code execution. The impact of this vulnerability depends heavily on how the application utilizes properties of `Object.prototype`. Given the widespread use of `convict` for configuration management in Node.js applications, a successful attack could compromise numerous systems across various sectors.

## Recommendation

*   Upgrade the `convict` npm package to a version greater than 6.2.4 to remediate CVE-2026-33863.
*   Implement strict input validation to sanitize data before passing it to `load()`, `loadFile()`, or `convict({...})`, as described in the advisory.
*   Deploy the Sigma rule to detect attempts to write to `Object.prototype` via configuration files in web server logs.
