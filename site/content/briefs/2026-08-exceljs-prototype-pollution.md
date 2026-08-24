---
title: Prototype Pollution Vulnerability in exceljs-hardened
slug: 2026-08-exceljs-prototype-pollution
description: The exceljs-hardened library before version 5.0.0 is vulnerable to prototype pollution, allowing unauthenticated remote attackers to inject malicious properties into Object.prototype via crafted cell note data.
date: "2026-08-24T01:40:00Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - exceljs-hardened
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can assign parsed JSON with a malicious __proto__ property to cell notes, modifying Object.prototype and affecting all plain objects created in the process.
    confidence_band: high
cves:
  - id: CVE-2026-78207
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78207
  - https://github.com/mateocallec/exceljs-hardened/security/advisories/GHSA-qwr4-7h29-chpf
  - https://www.vulncheck.com/advisories/exceljs-through-prototype-pollution-via-deepmerge-reached-from-note-serialization
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade exceljs-hardened to version 5.0.0 or higher across all development and production environments.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-78207 fix is released in version 5.0.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade dependencies and perform regression testing on spreadsheet processing logic.
      owner: Application Security
      addresses: CVE-2026-78207
      evidence: Source advisory recommends version 5.0.0.
---

The exceljs-hardened library, a hardened fork of the popular exceljs Node.js package, contains a critical prototype pollution vulnerability (CVE-2026-78207) in its `deepMerge` helper function. The vulnerability exists because the function fails to sanitize or reject sensitive keys such as `__proto__`, `constructor`, or `prototype` during the merging of JSON objects representing Excel cell notes. An attacker capable of influencing the input parsed by the library can leverage this flaw to pollute the global `Object.prototype`. Once the prototype is polluted, the attacker can modify the behavior of all plain objects within the JavaScript application's process. This can lead to various outcomes depending on the application logic, including remote code execution (RCE) if the application relies on polluted properties for security-sensitive checks, or service disruption. The issue impacts all versions prior to 5.0.0.

## Attack Chain

1. The application parses untrusted user-supplied JSON data intended for Excel file generation or processing.
2. The attacker crafts a malicious JSON payload containing a `__proto__` property with arbitrary nested attributes.
3. The malicious payload is passed to the `exceljs-hardened` library for processing as a cell note object.
4. The `deepMerge` helper function is invoked to merge the object properties.
5. The function fails to identify or block the `__proto__` key during the recursive merge process.
6. The `Object.prototype` is modified with the malicious property defined by the attacker.
7. The application subsequently performs operations on other objects that inherit from the modified prototype.
8. The attacker achieves code execution or logic bypass by influencing the application's processing of these polluted objects.

## Impact

Successful exploitation of CVE-2026-78207 allows an attacker to manipulate the execution environment of a Node.js application. While the direct impact is prototype pollution, this vulnerability serves as a primitive for more severe attacks, such as cross-site scripting (XSS), bypass of security controls, or remote code execution, depending on how the application handles object properties. Any Node.js-based web service that utilizes `exceljs-hardened` to process user-provided spreadsheet files is at risk.

## Recommendation

* Update the `exceljs-hardened` dependency to version 5.0.0 or later immediately to include the required sanitization patches for the `deepMerge` helper.
* Audit application code for usage of `exceljs-hardened` to confirm exposure and ensure that user-supplied input is validated before being passed to library functions.
* Implement Input Validation and Sanitization for all JSON objects processed by the library.
* Restrict the ability of untrusted users to upload or modify spreadsheet content processed by the application.
