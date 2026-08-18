---
title: Path Traversal in @rhinostone/swig Template Engine
slug: 2026-08-rhinostone-swig-traversal
description: The @rhinostone/swig template engine (CVE-2023-25345) contains a path traversal vulnerability in its filesystem loader, allowing unauthenticated attackers to read arbitrary local files via include or extends tags.
date: "2026-08-18T21:00:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:swig-templates_project:swig-templates:*:*:*:*:*:*:*:*
  - cpe:2.3:a:swig_project:swig:*:*:*:*:*:*:*:*
tags:
  - directory-traversal
  - arbitrary-file-read
  - template-injection
  - cve-2023-25345
products:
  - '@rhinostone/swig'
  - '@rhinostone/swig-core'
  - '@rhinostone/swig-twig'
  - '@rhinostone/swig-jinja2'
  - '@rhinostone/swig-django'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The loader fails to properly restrict file access to the configured template root directory when processing include, extends, and import tags.
    confidence_band: high
cves:
  - id: CVE-2023-25345
    cvss: 7.5
    epss: 0.01042
references:
  - https://github.com/advisories/GHSA-2mf3-mr2r-r4vf
  - https://nvd.nist.gov/vuln/detail/CVE-2023-25345
  - https://github.com/gina-io/swig/commit/381bdc305e0b10e45368d56324328b9b4f7017fc
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Update all instances of @rhinostone/swig and core components to version 2.7.2
      owner: Development
      due: 48h
      evidence: Fixed in 2.7.1, 2.7.2 resolves a subsequent regression
  mitigation_plan:
    - priority: immediate
      action: Sanitize all user input passed to template rendering logic
      owner: Development
      addresses: CVE-2023-25345
      evidence: Never pass untrusted data into an include/extends/import path
---

The `@rhinostone/swig` package, a maintained fork of the legacy `swig` template engine, inherits a path traversal vulnerability originally documented as CVE-2023-25345. The vulnerability manifests within the filesystem loader's handling of `{% include %}`, `{% extends %}`, and `{% import %}` tags. When processing these tags, the engine fails to validate that the requested template path remains within the defined template root directory.

An attacker who can influence the path string, either through application logic that maps user-supplied data to template variables or by exploiting direct template manipulation, can insert traversal sequences like `../` to escape the root directory. This allows the reading of sensitive host files, such as `/etc/passwd` or application configuration files, which are subsequently returned in the rendered HTTP response. The flaw affects the primary `@rhinostone/swig` package and its core loader component, as well as several derivative engines including `swig-twig`, `swig-jinja2`, and `swig-django`.

## Impact

Successful exploitation results in arbitrary local file disclosure. Depending on the server's permissions, this enables the exfiltration of critical information including application source code, database credentials, environment variables, and system-level configuration files. The impact is primarily on the confidentiality of the application and the host server.

## Recommendation

Prioritized actions for security teams:
- Immediately update `@rhinostone/swig` and related packages to version `2.7.2` or later to mitigate CVE-2023-25345 while avoiding the regression introduced in `2.7.1`.
- Audit application code for any instances where user-supplied input is directly passed as a variable into template include/extends tags.
- Configure the filesystem loader with an explicit and restrictive basepath if an immediate update is not feasible.
