---
title: Remote Code Execution in atomic-agents-stack via Insecure MCP Registry
slug: 2026-08-atomic-agents-rce
description: The atomic-agents-stack library is vulnerable to remote code execution due to insecure handling of cleartext HTTP connections for MCP registry catalogs, allowing a Man-in-the-Middle attacker to inject malicious commands.
date: "2026-08-18T00:47:05Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - atomic-agents
products:
  - atomic-agents-stack (1.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Catalog entries carry command/args that are type-validated but content-unrestricted, and are later spawned as local stdio subprocesses by MCPClientPool.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557.001
    technique_name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
    evidence: Over a cleartext http:// catalog URL, a network man-in-the-middle can rewrite the catalog response to inject an arbitrary command/args.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xhcr-cqfr-m3hv
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for systems utilizing atomic-agents-stack and restrict network access to non-HTTPS registry catalog endpoints.
      owner: IT Operations
      due: 24h
      evidence: Library permits cleartext http:// catalog URLs which enables MITM interception.
  mitigation_plan:
    - priority: immediate
      action: Upgrade atomic-agents-stack to the version requiring HTTPS and configure mcp_allow_fn with an allowlist.
      owner: IT Operations
      addresses: atomic-agents-stack
      evidence: Fix documented in GHSA-xhcr-cqfr-m3hv.
---

The atomic-agents-stack library, specifically the `make_http_mcp_server_registry_backend_from_url` function within `mcp_registry/http.py`, fails to enforce secure transport protocols. The implementation permits both `http` and `https` schemes when fetching MCP catalog registry entries. Because catalog entries specify command arguments that are subsequently executed as local subprocesses by `MCPClientPool`, this flaw creates an RCE primitive for a Man-in-the-Middle (MITM) attacker.

An attacker positioned on the network path between the agent host and the catalog registry can intercept the cleartext HTTP response and modify the provided `command` and `args` fields. Since the default configuration for `mcp_allow_fn` is `None`, the agent does not restrict which commands are executed upon resolution. This vulnerability affects all versions of atomic-agents-stack through 1.0.0. The impact is significant as it allows arbitrary code execution on the agent host without requiring LLM-level interaction.

## Impact

Successful exploitation allows an unauthenticated network attacker to achieve remote code execution on the host running the atomic-agents-stack. This bypasses security expectations by executing commands defined by an untrusted remote catalog, potentially leading to full system compromise or lateral movement within the environment.

## Recommendation

- Update atomic-agents-stack to a patched version that mandates HTTPS and enforces explicit opt-ins for HTTP registry URLs.
- Implement a mandatory allowlist function for `mcp_allow_fn` to validate the basename of any command resolved from external registry sources before subprocess spawning.
- Restrict network egress for agent hosts to only trusted, HTTPS-enabled registry endpoints to mitigate the risk of MITM interception of catalog responses.
