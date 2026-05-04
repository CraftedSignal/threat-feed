---
title: NetBox RCE via Jinja2 Template Injection (CVE-2026-29514)
slug: 2026-05-netbox-rce
description: NetBox versions 4.3.5 through 4.5.4 are vulnerable to remote code execution (RCE) via template injection, where authenticated users with specific permissions can inject malicious Python callables into template parameters, bypassing Jinja2 sandboxing to execute arbitrary code.
date: "2026-05-04T17:16:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - template-injection
  - netbox
  - cve-2026-29514
vendors:
  - NetBox
products:
  - NetBox (4.3.5 - 4.5.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
cves:
  - id: CVE-2026-29514
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29514
rules:
  - title: Detect NetBox Template Injection via environment_params
    description: Detects attempts to inject malicious Python callables into the environment_params field in NetBox, exploiting CVE-2026-29514.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect NetBox Template Injection - finalize Parameter
    description: Detects attempts to set the 'finalize' parameter to potentially dangerous functions like subprocess.getoutput, indicating a template injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

NetBox, a widely-used infrastructure resource modeling application, is vulnerable to remote code execution (RCE) in versions 4.3.5 through 4.5.4. This vulnerability, identified as CVE-2026-29514, resides in the `RenderTemplateMixin.get_environment_params()` method. An authenticated attacker with `exporttemplate` or `configtemplate` permissions can exploit this flaw by injecting malicious Python callables into the `environment_params` field. Successful exploitation allows the attacker to bypass the Jinja2 SandboxedEnvironment, achieving arbitrary code execution as the NetBox service user. This RCE can lead to complete system compromise, data exfiltration, or denial of service. Defenders should prioritize patching and implement the detection measures outlined below.

## Attack Chain

1. An authenticated user logs into the NetBox web application with `exporttemplate` or `configtemplate` permissions.
2. The attacker crafts a malicious request to modify or create an export/config template.
3. Within the request, the attacker injects a Python callable, such as `subprocess.getoutput`, into the `environment_params` field. The `finalize` parameter of the Jinja2 environment is set to this callable.
4. NetBox processes the request, and the Jinja2 environment is initialized with the attacker-controlled `finalize` parameter.
5. When the template is rendered, every expression outside the sandbox's call interception mechanism is processed.
6. The injected callable (`subprocess.getoutput`) is invoked on the rendered expression.
7. The `subprocess.getoutput` callable executes arbitrary shell commands as the NetBox service user.
8. The attacker gains remote code execution, potentially leading to full system compromise or data exfiltration.

## Impact

Successful exploitation of CVE-2026-29514 allows an authenticated attacker to execute arbitrary code on the NetBox server. The impact includes potential full system compromise, data exfiltration, and denial of service. Given that NetBox is often used to manage critical infrastructure information, a successful attack could have significant consequences, potentially affecting numerous organizations that rely on accurate network data.

## Recommendation

*   Upgrade NetBox to a patched version (4.5.5 or later) to remediate CVE-2026-29514.
*   Implement the provided Sigma rule to detect attempts to inject malicious callables into `environment_params` via webserver logs.
*   Review and restrict `exporttemplate` and `configtemplate` permissions to only those users who require them.
