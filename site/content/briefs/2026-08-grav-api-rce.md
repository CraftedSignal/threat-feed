---
title: Remote Code Execution in Grav API Plugin via Privilege Escalation
slug: 2026-08-grav-api-rce
description: The Grav API plugin before version 1.0.13 fails to enforce API key scope restrictions in ConfigController, enabling remote code execution via injected scheduler commands.
date: "2026-08-14T14:11:46Z"
lastmod: "2026-08-18T12:53:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - privilege-escalation
  - web-application-vulnerability
vendors:
  - GetGrav
products:
  - Grav API plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Grav API plugin fails to enforce API key scope caps in ConfigController, allowing remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers with a scoped api.config.write key can inject arbitrary commands into scheduler.custom_jobs that execute via Symfony Process.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any authenticated caller with api.access can therefore invoke a privileged menubar action directly, bypassing the intended authorization.
    confidence_band: high
cves:
  - id: CVE-2026-72830
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72830
  - https://github.com/getgrav/grav/security/advisories/GHSA-2x29-3mjq-2pvx
  - https://www.vulncheck.com/advisories/grav-api-plugin-before-rce-via-configcontroller-scope-bypass
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75836
rules:
  - title: Detects CVE-2026-72830 Exploitation - API Configuration Injection
    description: Detects attempts to modify scheduler configuration via the Grav API ConfigController with potential command injection indicators
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-18T12:53:39Z"
    level: L2
    summary: added coverage for Grav API plugin
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75836
---

Grav API plugin versions before 1.0.13 are susceptible to a privilege management vulnerability (CWE-269) located in the ConfigController component. The plugin fails to adequately enforce scope restrictions for API keys, specifically regarding the 'api.config.write' permission. An attacker possessing a restricted API key with this scope can bypass intended access controls to modify the site's scheduler configuration. By manipulating the 'scheduler.custom_jobs' parameter, an attacker can inject arbitrary shell commands. These commands are subsequently executed by the underlying Symfony Process component, resulting in remote code execution (RCE) on the host server. This vulnerability is highly critical due to the potential for unauthenticated or low-privilege access to lead to full system compromise. Users of the Grav API plugin must upgrade to version 1.0.13 or later immediately to remediate this flaw.

## Attack Chain

1. Attacker obtains or identifies an API key possessing the 'api.config.write' scope.
2. Attacker crafts a malicious HTTP POST request targeting the ConfigController endpoint.
3. The request includes a modified payload for the 'scheduler.custom_jobs' configuration setting.
4. The Grav API plugin fails to validate the key scope against the requested action.
5. The malicious configuration is saved to the backend storage by the vulnerable ConfigController.
6. The application invokes the scheduler service which reads the injected 'custom_jobs' entry.
7. The system executes the injected commands via the Symfony Process component.
8. Attacker achieves remote code execution in the context of the web server process.

## Impact

Successful exploitation allows for full remote code execution on the server hosting the Grav instance. This can lead to unauthorized data access, system-wide configuration changes, or complete compromise of the web server, potentially impacting all data processed by the affected Grav deployment.

## Recommendation

Prioritized actions for detection and remediation:
- Update the Grav API plugin to version 1.0.13 or later across all environments immediately.
- Audit all active API keys, specifically those with 'api.config.write' scope, and revoke any that appear suspicious or are no longer required.
- Deploy the provided Sigma rule to monitor for suspicious API configuration changes that include command execution patterns.
- Enable web server access logs and monitor for POST requests targeting the Grav API 'ConfigController' endpoint originating from unusual or untrusted sources.
