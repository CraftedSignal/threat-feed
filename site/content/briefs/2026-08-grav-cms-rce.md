---
title: Arbitrary Static Method Execution in Grav CMS
slug: 2026-08-grav-cms-rce
description: Grav CMS versions 2.0.7 through 2.0.10 allow authenticated users with page-editing permissions to trigger arbitrary public static method calls via malicious blueprint directives, leading to unauthorized file read and write operations.
date: "2026-08-03T16:06:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cms
  - rce
  - file-read
  - web-application
vendors:
  - Grav
products:
  - Grav CMS (2.0.7 - 2.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An account with only page-editing rights can plant a directive in a page's form-field frontmatter that invokes an arbitrary public static PHP method.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This allows reading of any server-readable file and arbitrary creation/copying of files and directories under the web-server account.
    confidence_band: high
cves:
  - id: CVE-2026-69088
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69088
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch Grav CMS to version 2.0.11
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.0.11.
  mitigation_plan:
    - priority: immediate
      action: Audit user permissions for admin.pages access
      owner: IT Operations
      addresses: CVE-2026-69088
      evidence: An account with only page-editing rights (admin.pages) can plant a directive.
---

Grav CMS versions 2.0.7 through 2.0.10 are vulnerable to an arbitrary static method execution flaw (CVE-2026-69088). The vulnerability stems from insufficient input validation in the `Blueprint::isSafeDynamicCall()` function. While the application implements a denylist for dangerous callables, this protection is bypassed when a fully-qualified static method call (using the `Class::method` syntax) is utilized, as the validation check fails to evaluate strings containing the double-colon delimiter.

An attacker with administrative page-editing access (`admin.pages`) can inject a malicious directive into the form-field frontmatter of a page. When the application parses this blueprint, it executes the specified static method. By leveraging existing gadget methods within the PHP environment, an attacker can read arbitrary files accessible to the web server user or perform file/directory creation and modification. This effectively elevates privileges for a low-privileged editor to perform sensitive system operations. The issue is resolved in Grav CMS version 2.0.11.

## Impact

Successful exploitation allows an attacker to read any file on the server readable by the web server process and perform unauthorized file and directory operations. This can lead to the exfiltration of sensitive configuration files, source code, or internal data, as well as the modification of the web root to achieve persistent code execution. This vulnerability is particularly critical in multi-user environments where page-editing permissions are delegated to non-administrative users.

## Recommendation

1. Upgrade all instances of Grav CMS to version 2.0.11 or later immediately to patch CVE-2026-69088.
2. Review system logs for unexpected modification of configuration files or directory structures within the web root.
3. Audit administrative user accounts to ensure that page-editing privileges are granted only to trusted personnel.
4. Restrict file system permissions for the web server user to the minimum necessary to function, specifically limiting write access to only required directories, to mitigate the impact of arbitrary file operations.
