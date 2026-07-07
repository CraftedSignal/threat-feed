---
title: Incomplete Fix for CVE-2026-25754 in @adonisjs/bodyparser Leads to CVE-2026-48795
slug: 2026-07-adonisjs-bodyparser-incomplete-fix
description: An incomplete fix for CVE-2026-25754 in the `@adonisjs/bodyparser` package, tracked as CVE-2026-48795, allows remote unauthenticated attackers to bypass security measures via nested prototype pollution payloads in `multipart/form-data` requests, potentially leading to authorization bypasses or remote code execution.
date: "2026-07-03T13:04:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adonisjs:bodyparser:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next1:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next2:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next3:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next4:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next5:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next6:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next7:*:*:*:node.js:*:*
  - cpe:2.3:a:adonisjs:bodyparser:11.0.0:next8:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - web-vulnerability
  - adonisjs
  - rce
vendors:
  - AdonisJS
products:
  - '@adonisjs/bodyparser (>= 10.1.3 < 10.1.5)'
  - '@adonisjs/bodyparser (>= 11.0.0-next.9 < 11.0.3)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This issue is exploitable remotely through a single unauthenticated `multipart/form-data` request using the default configuration.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Because the pollution is process-wide, the impact may include authorization bypasses
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: or prototype pollution gadget chains leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-25754
    cvss: 7.2
    epss: 0.00364
references:
  - https://github.com/advisories/GHSA-qcm7-3vpr-hj5h
  - https://cwe.mitre.org/data/definitions/1321.html
  - https://github.com/adonisjs/core/security/advisories/GHSA-f5x2-vj4h-vg4c
  - https://github.com/adonisjs/bodyparser/releases/tag/v10.1.5
  - https://github.com/adonisjs/bodyparser/releases/tag/v11.0.3
---

The `@adonisjs/bodyparser` package for AdonisJS applications contains a critical vulnerability, CVE-2026-48795, which is an incomplete fix for a previously identified prototype pollution flaw (CVE-2026-25754). This vulnerability affects versions `>= 10.1.3 < 10.1.5` and `>= 11.0.0-next.9 < 11.0.3`. An unauthenticated attacker can remotely exploit this by sending a specially crafted `multipart/form-data` request. The bypass occurs because the underlying `lodash.set()` utility, used via `@poppinss/utils`, still creates intermediate objects that regain access to `Object.prototype` when payloads like `user.__proto__.polluted` are used. This allows for process-wide `Object.prototype` pollution, which can have severe consequences for the affected application, including authorization bypasses, unexpected behavior, or even remote code execution via gadget chains.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable AdonisJS application accepting `multipart/form-data` requests.
2.  The attacker crafts an HTTP POST request with a `multipart/form-data` content type.
3.  The request body contains a form field whose name is a prototype pollution payload, structured to bypass the original fix, such as `user.__proto__.polluted`.
4.  The vulnerable `@adonisjs/bodyparser` component processes the incoming `multipart/form-data` request.
5.  During parsing, `@adonisjs/bodyparser` utilizes `lodash.set()` (via `@poppinss/utils`) to construct form fields.
6.  `lodash.set()` creates intermediate objects using plain `{}` values, which re-introduce the `Object.prototype` into the inheritance chain once a "normal" segment (e.g., `user`) is processed before `__proto__`.
7.  This action successfully pollutes the global `Object.prototype` within the application's process.
8.  The polluted `Object.prototype` can then be leveraged by the attacker to trigger authorization bypasses, unexpected application behavior, or remote code execution by exploiting existing prototype pollution gadget chains.

## Impact

Successful exploitation of CVE-2026-48795 grants an unauthenticated attacker the ability to pollute the `Object.prototype` across the entire application process. This critical issue means that any route accepting `multipart/form-data` requests behind `BodyParserMiddleware` is vulnerable. The direct consequences can include authorization bypasses, allowing attackers to gain unauthorized access or elevate privileges within the application. Furthermore, the pollution can cause unpredictable behavior in various downstream libraries or enable exploitation of prototype pollution gadget chains, potentially leading to full remote code execution on the server hosting the AdonisJS application.

## Recommendation

*   Patch CVE-2026-48795 immediately by upgrading `@adonisjs/bodyparser` to version `10.1.5` or `11.0.3` or later.
*   Review application logs for `multipart/form-data` POST requests containing `__proto__` or `constructor.prototype` in form field names, indicative of attempted exploitation.
