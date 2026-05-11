---
title: python-liquid FileSystemLoader Absolute Path Escape Vulnerability
slug: 2026-05-python-liquid-path-escape
description: The FileSystemLoader in python-liquid versions before 2.2.0 allows malicious template authors to read arbitrary files outside the search paths via the `{% include %}` and `{% render %}` tags by using absolute paths; this is resolved in version 2.2.0 by checking for absolute paths in the `resolve_path()` method.
date: "2026-05-11T14:58:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - template-injection
  - CVE-2026-45017
vendors:
  - pip
products:
  - python-liquid (< 2.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8p4x-wr7x-3788
rules:
  - title: Detect CVE-2026-45017 Attempt — python-liquid FileSystemLoader Absolute Path
    description: Detects CVE-2026-45017 exploitation attempt — web requests containing absolute paths in template names when using python-liquid FileSystemLoader
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45017 Attempt — python-liquid Template Include Absolute Path
    description: Detects CVE-2026-45017 exploitation attempt — absolute paths in template include directives when using python-liquid
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The python-liquid library, a template engine, is vulnerable to a path traversal issue affecting the `FileSystemLoader` and `CachingFileSystemLoader` classes. Versions prior to 2.2.0 fail to properly sanitize template paths, allowing an attacker to specify absolute paths via the `{% include %}` and `{% render %}` tags. This vulnerability, identified as CVE-2026-45017, allows a malicious template author to potentially read any file on the system that contains valid Liquid markup and is readable by the application process. The fix, implemented in version 2.2.0, adds a check for absolute paths in the `resolve_path()` method within `liquid/builtin/loaders/file_system_loader.py`. This prevents the loader from processing templates located outside the intended search paths.

## Attack Chain

1. An attacker gains the ability to author or modify Liquid templates used by an application using python-liquid.
2. The attacker crafts a malicious template containing an `{% include %}` or `{% render %}` tag.
3. The tag's argument specifies an absolute path to a file outside the intended template directory, such as `/etc/passwd` or `C:\\boot.ini`.
4. The application processes the malicious template using the `FileSystemLoader` or `CachingFileSystemLoader`.
5. The vulnerable loader resolves the attacker-supplied absolute path without proper validation.
6. The loader reads the contents of the arbitrary file specified by the absolute path.
7. The application renders the template, potentially exposing the contents of the arbitrary file to an unauthorized user or system.
8. If the targeted file contains valid Liquid markup, it is rendered as part of the template. Otherwise, the raw contents are displayed.

## Impact

Successful exploitation of CVE-2026-45017 allows an attacker to bypass intended security restrictions and read arbitrary files on the system. The severity of the impact depends on the contents of the files accessed. Sensitive information, such as configuration files, credentials, or internal application code, could be exposed. The number of victims is dependent on the number of applications utilizing python-liquid with user-supplied template content.

## Recommendation

*   Upgrade to python-liquid version 2.2.0 or later to remediate CVE-2026-45017, which patches the vulnerability in the `FileSystemLoader` class.
*   As an interim workaround if patching is not immediately feasible, implement a custom template loader as described in the advisory, which overrides the `resolve_path()` method to prevent absolute paths.
*   Deploy the Sigma rule "Detect CVE-2026-45017 Attempt — python-liquid FileSystemLoader Absolute Path" to identify attempts to exploit this vulnerability in web server logs.
