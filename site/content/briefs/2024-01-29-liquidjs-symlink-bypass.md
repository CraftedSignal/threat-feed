---
title: LiquidJS Template Engine Root Restriction Bypass via Symlink Exploitation
slug: 2024-01-29-liquidjs-symlink-bypass
description: A vulnerability in LiquidJS allows attackers to bypass template root restrictions by using symlinks within allowed directories to render arbitrary files outside the intended scope, potentially leading to sensitive information disclosure.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - liquidjs
  - symlink
  - template-injection
  - root-restriction-bypass
vendors:
  - LiquidJS
products:
  - LiquidJS Template Engine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://github.com/advisories/GHSA-56p5-8mhr-2fph
rules:
  - title: Detect LiquidJS Template Rendering with Suspicious File Paths
    description: Detects LiquidJS template rendering using include, render or layout tags with file paths containing '..', potentially indicating directory traversal or symlink exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Symlink Creation in Template Directories
    description: Detects the creation of symlinks within directories commonly used for LiquidJS templates, which might indicate an attempt to bypass security restrictions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - file_event
      - linux
rules_count: 2
---

LiquidJS, a popular template engine, is susceptible to a root restriction bypass (CVE-2026-35525) affecting versions 10.25.2 and below. The vulnerability stems from how LiquidJS handles partials and layouts. Specifically, it validates access based on the pathname string rather than resolving the canonical filesystem path. This allows an attacker to place a symlink within an allowed directory (partials or layouts) that points to a file outside of that directory. When LiquidJS attempts to render the template, it follows the symlink, effectively bypassing the intended root restriction. This issue arises in environments where attackers can influence template files, such as through uploaded themes, extracted archives, or repository-controlled template trees.

## Attack Chain

1.  The attacker gains the ability to influence or place files within a LiquidJS template directory. This could be via uploading themes, extracting archives, or modifying content within a repository.
2.  The attacker creates a symlink file, `link.liquid`, within the allowed `partials` or `layouts` directory.
3.  The symlink `link.liquid` is configured to point to a sensitive file outside the allowed template root (e.g., `/etc/passwd`).
4.  The attacker crafts a LiquidJS template containing an `{% include %}`, `{% render %}`, or `{% layout %}` tag that references the symlink `link.liquid`.
5.  LiquidJS processes the template and performs a path-based check on `link.liquid`, which passes because it resides within the allowed directory.
6.  When LiquidJS attempts to read the template, the filesystem resolves the symlink to the targeted file (e.g., `/etc/passwd`).
7.  LiquidJS renders the contents of the targeted file as part of the template output.
8.  The attacker gains access to the content of the sensitive file, potentially revealing sensitive information or configuration details.

## Impact

Successful exploitation allows attackers to read arbitrary files accessible to the LiquidJS process. This could lead to the disclosure of sensitive information such as configuration files, source code, or internal documentation. The impact is particularly severe in environments where LiquidJS is used to render user-supplied templates, as it enables privilege escalation or information leakage. The vulnerable package, `npm/liquidjs` (versions <= 10.25.2), is widely used in web applications.

## Recommendation

*   Upgrade LiquidJS to a version greater than 10.25.2 to remediate CVE-2026-35525.
*   Implement stricter file access controls and input validation to prevent attackers from placing or influencing files in template directories.
*   Monitor filesystem events for the creation of symlinks within template directories that point outside the allowed root. Use the `FileCreate` and `TargetFilename` fields in the provided Sigma rule to detect symlink creation.
*   Deploy the Sigma rules provided to detect the usage of `render`, `include`, or `layout` tags referencing suspicious file paths in your environment.
