---
title: Arbitrary File System Access via Hugo Build Process
slug: 2026-09-hugo-exec-bypass
description: Hugo versions 0.43 through 0.164.0 include TailwindCSS in the default allowed execution list, enabling Node-based tools to bypass sandbox restrictions and perform unauthorized file read/write operations.
date: "2026-09-11T13:12:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gohugo:hugo:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - supply-chain
  - static-site-generator
vendors:
  - Hugo
products:
  - Hugo (>= 0.43, < 0.165.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Hugo executes Node tools under Node's permission model, allowing a Node tool invoked during a build to read and write files outside the project's working directory.
    confidence_band: high
cves:
  - id: CVE-2026-89259
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89259
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade Hugo to version 0.165.0 or later
      owner: DevOps
      due: 48h
      evidence: The issue was fixed in v0.165.0 by removing tailwindcss from the default security.exec.allow list.
  mitigation_plan:
    - priority: immediate
      action: Modify hugo.toml to restrict security.exec.allow
      owner: DevOps
      addresses: CVE-2026-89259
      evidence: As a workaround, users can define a restrictive security.exec.allow list in hugo.toml.
---

Hugo, a popular static site generator, introduced a vulnerability in versions 0.43 through 0.164.0 due to an overly permissive default configuration. The application's `security.exec.allow` list included TailwindCSS, which necessitates highly permissive Node.js runtime flags, specifically --allow-addons, --allow-child-process, and --allow-worker. Because these flags were implicitly enabled for TailwindCSS within the Hugo build process, any malicious or compromised Node-based tool invoked during site generation could bypass security sandboxing intended to limit execution scope. This flaw allows an attacker to manipulate the build process to perform arbitrary file reads and writes outside of the project's intended working directory. This vulnerability was addressed in Hugo version 0.165.0 by removing TailwindCSS from the default allowed execution list.

## Impact

Successful exploitation allows an attacker to achieve unauthorized file system access on the machine performing the build. In CI/CD environments where Hugo is used to generate documentation or site content, this could lead to the exfiltration of sensitive source code, configuration secrets, or the injection of malicious content into the final static site artifacts.

## Recommendation

1. Upgrade Hugo to version 0.165.0 or later to ensure TailwindCSS is removed from the default allowed execution list.
2. For users unable to upgrade, manually override the configuration by defining a restrictive `security.exec.allow` list in the `hugo.toml` file to explicitly exclude unnecessary or insecure tools.
3. Audit build logs for CI/CD pipelines to identify if Node-based tools are being executed with unexpected flags or accessing paths outside the project root.
