---
title: Flowise Unauthenticated RCE via Environment Variable Bypass
slug: 2026-08-flowise-rce
description: Flowise v3.1.2 and earlier are vulnerable to unauthenticated remote code execution because the CVE-2025-8943 patch relies on an incomplete environment variable blocklist, allowing attackers to inject configuration variables that force arbitrary package installation.
date: "2026-08-04T17:24:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*
tags:
  - rce
  - injection
  - flowise
  - cve-2026-69263
vendors:
  - Flowise
products:
  - Flowise (3.1.2)
  - Flowise Components (3.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following variables are also absent from the blocklist and influence execution through the other permitted interpreters.
    confidence_band: high
cves:
  - id: CVE-2025-8943
    cvss: 9.8
    epss: 0.7231
  - id: CVE-2026-69263
references:
  - https://github.com/advisories/GHSA-xc48-889x-5qmw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69263
  - https://nvd.nist.gov/vuln/detail/CVE-2025-8943
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Flowise to the latest patched release immediately
      owner: IT Operations
      due: 24h
      evidence: Flowise (<= 3.1.2) is vulnerable to unauthenticated RCE
  mitigation_plan:
    - priority: immediate
      action: Enable authentication for the Flowise instance if currently unauthenticated
      owner: IT Operations
      addresses: Unauthenticated API access
      evidence: On a default deployment with no authentication, any unauthenticated user who can reach the Flowise API can trigger this.
---

Flowise (v3.1.2 and earlier) contains a critical security flaw involving an incomplete environment variable blocklist, identified as CVE-2026-69263. This vulnerability allows an attacker to bypass the intended security controls for the Model Context Protocol (MCP) server configuration, specifically those established in the previous CVE-2025-8943 patch. While the original patch successfully filtered dangerous CLI flags like `-y` for `npx`, it failed to account for `npm` configuration that can be passed via environment variables (e.g., `npm_config_yes`).

Because Flowise defaults to an unauthenticated state, a remote attacker can interact with the API to register a malicious MCP server. By including specific environment variables in the configuration, an attacker can influence the behavior of `npx`, `node`, or `python3` to achieve remote code execution. This is a classic case of incomplete denylisting, where developers attempted to enumerate dangerous inputs rather than implementing a secure allowlist, leaving the environment vulnerable to various configuration injection vectors.

## Attack Chain

1. Attacker discovers an internet-facing, unauthenticated Flowise instance.
2. Attacker interacts with the Flowise API to create or update an MCP server configuration.
3. Attacker crafts a JSON payload containing the `mcpServers` object with a command like `npx`.
4. Attacker inserts environment variables such as `npm_config_yes=true` into the `env` field of the payload.
5. Flowise validation logic (`validateCommandFlags`) is bypassed because the CLI flags are clean.
6. Flowise validation logic (`validateEnvironmentVariables`) is bypassed because the blocklist only contains four hardcoded entries (PATH, LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, NODE_OPTIONS).
7. Flowise spawns the `npx` process, which reads the injected environment variable and proceeds with automatic package installation.
8. Malicious code is executed under the privileges of the Flowise process, resulting in full system compromise.

## Impact

Successful exploitation results in unauthenticated remote code execution on the server running Flowise. Given the tool's nature as an LLM integration platform, successful compromise often grants an attacker access to connected sensitive data, API keys for AI providers, and internal network resources. All versions up to and including 3.1.2 are confirmed to be vulnerable.

## Recommendation

1. Upgrade to a version of Flowise that implements an allowlist-based validation approach for environment variables rather than a denylist.
2. Implement strict authentication on all Flowise API endpoints to prevent unauthenticated access to configuration interfaces.
3. Restrict outbound network access for the server running Flowise to prevent the automatic installation of arbitrary npm/pip packages from the internet.
4. Ensure that the service account running the Flowise process operates with the principle of least privilege, minimizing the damage from a successful code execution event.
