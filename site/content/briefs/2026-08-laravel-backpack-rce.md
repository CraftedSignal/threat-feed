---
title: Remote Code Execution in Laravel Backpack via Host Header Injection
slug: 2026-08-laravel-backpack-rce
description: An unauthenticated command injection vulnerability in Laravel Backpack's Stats::makeCurlRequest method allows remote code execution by exploiting unsanitized Host header input passed to an exec() shell command.
date: "2026-08-20T19:13:33Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Backpack
products:
  - Backpack for Laravel
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A specially crafted Host header can break out of the shell argument and cause the server to execute arbitrary OS commands as the web user.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The vulnerable code path is reached from BackpackServiceProvider::boot() on every HTTP request in production when exec() and curl are available.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mrc5-3mm3-45c5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54182
rules:
  - title: Detect CVE-2026-54182 Exploitation - Host Header Command Injection
    description: Detects exploitation attempts against CVE-2026-54182 by monitoring for shell metacharacters in the Host header.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: 'Upgrade Backpack for Laravel to patched versions: 4.1.70, 5.6.2, 6.8.13, or 7.0.36.'
      owner: IT Operations
      due: 24h
      evidence: Fix section of the brief confirms removal of the vulnerable makeCurlRequest method.
  mitigation_plan:
    - priority: immediate
      action: Disable PHP exec() functions in production environment.
      owner: IT Operations
      addresses: CVE-2026-54182
      evidence: Source notes that exec() is often disabled in hardened environments to prevent this class of vulnerability.
---

Laravel Backpack contains a high-severity remote code execution vulnerability (CVE-2026-54182) within its `Stats::makeCurlRequest` method. The vulnerability arises because the package constructs a shell command using unescaped input derived from the HTTP `Host` header and executes it via the PHP `exec()` function. This vulnerability is reachable pre-authentication during the `BackpackServiceProvider::boot()` process, which executes on every request in production.

While the application includes a 1-in-100 random execution gate, attackers can trigger the exploit reliably through automated retries. Successful exploitation requires a server environment where the PHP `exec()` function is enabled and the web server (e.g., Nginx or Apache) fails to normalize or reject malformed `Host` headers. If these conditions are met, an attacker can gain command execution under the privileges of the web user, leading to full compromise of the application environment, including access to secrets stored in `.env` files and internal network resources.

## Attack Chain

1. Attacker identifies a target application running a vulnerable version of Backpack for Laravel.
2. Attacker crafts an HTTP request with a malicious `Host` header containing shell injection payloads (e.g., `; command; #`).
3. The request reaches the web server, which forwards the request to the PHP backend without stripping the malicious `Host` header.
4. `BackpackServiceProvider::boot()` is triggered during the standard request lifecycle.
5. The application execution hits the 1-in-100 random gate; the attacker retries the request until the logic proceeds to `Stats::makeCurlRequest`.
6. The `makeCurlRequest` method injects the header into a string passed to the PHP `exec()` function.
7. The operating system spawns a shell process to execute the injected payload with the privileges of the web server user.
8. The attacker achieves code execution to exfiltrate environment variables, modify local files, or move laterally within the network.

## Impact

Successful exploitation results in full unauthenticated remote code execution. Attackers can exfiltrate sensitive configuration data, including `APP_KEY`, database credentials, and third-party API keys. This provides a vector for full data exfiltration, service disruption, and potential lateral movement into internal infrastructure connected to the compromised web host. The number of affected deployments is widespread across applications utilizing the Backpack for Laravel framework.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Upgrade all instances of Backpack for Laravel to the patched versions (4.1.70, 5.6.2, 6.8.13, 7.0.36) immediately to remove the `makeCurlRequest` method.
* Audit web server configurations to ensure that `Host` headers are validated against an allowlist of expected domains and that invalid requests are dropped before reaching the application layer.
* Configure PHP to disable the `exec()`, `shell_exec()`, and `passthru()` functions in production environments if they are not strictly required for application functionality.
* Deploy web server logging to monitor for anomalous characters (semicolons, backticks, pipe symbols) within the `Host` header field of incoming HTTP requests.
