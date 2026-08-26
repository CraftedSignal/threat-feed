---
title: OS Command Injection in ClipBucket V5 Installer
slug: 2026-08-clipbucket-rce
description: ClipBucket V5 versions 5.5.1 through 5.5.3-#153 contain an OS command injection vulnerability in the web installer, allowing unauthenticated remote code execution via the php_cli_filepath parameter.
date: "2026-08-26T00:51:23Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - remote-code-execution
  - web-application-vulnerability
vendors:
  - MacWarrior
products:
  - clipbucket-v5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can submit a crafted POST request to the installer with a malicious php_cli_filepath value to execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The installer fails to properly validate or escape the php_cli_filepath parameter before passing it to shell execution.
    confidence_band: high
cves:
  - id: CVE-2026-80138
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80138
  - https://www.vulncheck.com/advisories/clipbucket-v5-5.5.1-through-5.5.3-153-os-command-injection-via-installer-php-cli-filepath-parameter
  - https://github.com/MacWarrior/clipbucket-v5/commit/36e7c6cfd81f62a091d2aeef96a8fc2fc2d85dc4
rules:
  - title: Detects CVE-2026-80138 Exploitation - OS Command Injection in ClipBucket Installer
    description: Detects exploitation of CVE-2026-80138 by monitoring for POST requests to the ClipBucket installer with shell metacharacters in the php_cli_filepath parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to /cb_install/ on all production servers.
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms unauthenticated RCE via installer path.
  hunt_leads:
    - lead: Search logs for POST /cb_install/ and shell metacharacters in request parameters.
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows remote command injection via this specific endpoint.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patch 36e7c6cfd81f62a091d2aeef96a8fc2fc2d85dc4.
      owner: IT Operations
      addresses: CVE-2026-80138
      evidence: Vendor-provided fix commit.
---

ClipBucket V5 (versions 5.5.1 through 5.5.3-#153) contains a critical OS command injection vulnerability (CVE-2026-80138) within its web-based installation script. The vulnerability resides in the handling of the 'php_cli_filepath' parameter, which is processed by the installer's 'cb_install/functions_install.php' file. Because the application fails to perform adequate validation or sanitization of this user-supplied input before passing it to system-level shell execution functions, an unauthenticated attacker can supply crafted input to execute arbitrary OS commands. 

Successful exploitation results in command execution with the privileges of the web server user. This vulnerability is particularly dangerous because it affects the initial setup phase of the application, potentially allowing an attacker to compromise the host before the administrator completes the installation process. Defenders should prioritize auditing web installer access and ensuring that software deployment instances are not exposed to the public internet during the configuration phase.

## Attack Chain

1. Attacker identifies a target server running an unconfigured or accessible ClipBucket V5 installer.
2. Attacker initiates an HTTP POST request to the web installer endpoint (typically located in the /cb_install/ directory).
3. Attacker injects shell metacharacters (e.g., ;, |, &&, `) into the 'php_cli_filepath' POST parameter.
4. The 'cb_install/functions_install.php' script receives the malicious input without validation.
5. The application passes the unsanitized string directly to a system shell execution function.
6. The underlying web server process (e.g., www-data, apache, or iis apppool) executes the injected commands.
7. Attacker achieves remote code execution to drop a web shell, exfiltrate data, or pivot within the environment.

## Impact

Successful exploitation grants an unauthenticated remote attacker full control over the web server process. In a typical web hosting environment, this facilitates unauthorized access to the application source code, configuration files (containing database credentials), and potentially the ability to move laterally into the internal network. Given the critical CVSS 9.8 score, this vulnerability represents a high risk of total system compromise for any organization running affected versions of ClipBucket.

## Recommendation

* Immediately restrict public access to the ClipBucket installation directory (/cb_install/) using web server authentication or network-level firewall controls.
* Upgrade to a version of ClipBucket V5 that incorporates the fix provided in commit 36e7c6cfd81f62a091d2aeef96a8fc2fc2d85dc4.
* Audit web server access logs for anomalous POST requests directed at the installer file path, specifically looking for shell-related special characters in the 'php_cli_filepath' parameter.
* Deploy the provided detection rule to monitor for exploitation attempts targeting the identified installer vulnerability.
