---
title: NodeVM Sandbox Escape via Unrestricted OS and DNS Built-ins
slug: 2026-08-vm2-nodevm-escape
description: 'The vm2 sandbox library fails to restrict the ''os'' and ''dns'' built-in modules when using the ''builtin: [''*'']'' configuration, enabling host-level information disclosure and process-wide DNS hijacking.'
date: "2026-08-17T18:45:33Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - vm2
  - nodejs
  - sandbox-escape
  - supply-chain
vendors:
  - vm2
products:
  - NodeVM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker invokes 'dns.setServers()' to point the host process's DNS resolution to an attacker-controlled resolver.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The attacker primitive is one synchronous line of sandbox code which is strictly worse than every read-only leak that GHSA-9g8x added.
    confidence_band: high
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: 'Audit vm2 configuration files across the organization to identify usage of ''builtin: [''*'']'''
      owner: SOC
      due: 24h
      evidence: 'Source explicitly identifies ''builtin: [''*'']'' as the configuration pattern that admits ''os'' and ''dns''.'
  mitigation_plan:
    - priority: immediate
      action: Explicitly exclude 'os' and 'dns' from the builtin configuration in all vm2 instances.
      owner: IT Operations
      addresses: NodeVM configuration
      evidence: Source recommends appending '-os' and '-dns' exclusions to the documented config.
---

The NodeVM component within the vm2 sandbox library contains a critical flaw where the 'os' and 'dns' built-in modules are not correctly identified as dangerous when using the 'builtin: ['*']' configuration. While prior security updates (GHSA-9g8x-92q2-p28f) restricted modules like 'diagnostics_channel' and 'perf_hooks' to prevent host-process state exposure, 'os' and 'dns' were omitted. Because NodeVM relies on a 'vm.readonly()' proxy, these modules expose host-process state that cannot be localized to the sandbox. Attackers can leverage 'os' to fingerprint the host environment (UID, GID, network interfaces) and 'dns.setServers()' to hijack DNS lookups for the entire host process. This allows for sophisticated supply-chain attacks, credential exfiltration, and service authentication subversion, effectively granting the sandboxed code control over the host's communication and configuration.

## Attack Chain

1. The attacker identifies an application leveraging vm2 with the 'builtin: ['*']' configuration.
2. The attacker injects malicious JavaScript into the sandboxed environment.
3. The attacker calls 'os.userInfo()' or 'os.networkInterfaces()' to perform host environment reconnaissance.
4. The attacker invokes 'dns.setServers()' to point the host process's DNS resolution to an attacker-controlled resolver.
5. The host process performs legitimate outbound requests (e.g., npm dependency installation, API calls, OIDC authentication).
6. The attacker's DNS resolver intercepts these queries and returns malicious IPs.
7. The host process connects to the attacker's infrastructure, facilitating data exfiltration, dependency substitution, or authentication bypass.

## Impact

Successful exploitation allows for full compromise of the host process's network communication, enabling credential theft, supply-chain attacks via malicious package substitution, and bypass of host-side security controls. This vulnerability affects any Node.js application utilizing vm2 for untrusted code execution, including webhooks and CI/CD runners, potentially impacting production environments hosting multiple tenants.

## Recommendation

Prioritize upgrading vm2 or modifying the 'builtin' allowlist immediately.
* Audit all vm2 configurations to identify instances using 'builtin: ['*']' and ensure '-os' and '-dns' are explicitly added to the exclusion list.
* Implement the following Sigma rule to detect attempts to invoke sensitive 'os' or 'dns' methods within a sandboxed environment if logs are instrumented.
* Monitor host process DNS configurations or anomalies in outbound HTTP request patterns for hosts running untrusted code.
