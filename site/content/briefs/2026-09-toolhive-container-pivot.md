---
title: ToolHive Containerized MCP Servers Vulnerable to Host Pivot and Lateral Movement
slug: 2026-09-toolhive-container-pivot
description: ToolHive versions prior to 0.30.1 enable insecure container network defaults that allow MCP servers to reach host services via host.docker.internal, enabling unauthenticated lateral movement and host API exploitation.
date: "2026-09-18T19:51:12Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:stacklok:toolhive:*:*:*:*:*:*:*:*
tags:
  - container-security
  - mcp
  - lateral-movement
  - cve-2026-58197
vendors:
  - Stacklok
products:
  - ToolHive (< 0.30.1)
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: A malicious containerized MCP server can call privileged tools (e.g., execute_command('rm -rf /')) or write_file('/etc/crontab').
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: A malicious containerized MCP server can port-scan host.docker.internal to discover listening services.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: The attacker uses wget to perform JSON-RPC handshakes over HTTP/HTTPS against host-local services.
    confidence_band: high
cves:
  - id: CVE-2026-58197
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-qg2g-g9w3-m5h8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58197
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all ToolHive installations to version 0.30.1
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerable version is < 0.30.1
  mitigation_plan:
    - priority: immediate
      action: Restrict container network access to host-local services
      owner: Security Operations
      addresses: CVE-2026-58197
      evidence: Suggested mitigation section in advisory
---

ToolHive versions prior to 0.30.1 feature insecure default container networking configurations. By default, MCP servers run with an 'insecure_allow_all' permission profile, allowing containerized processes to communicate with the host machine via the Docker-provided 'host.docker.internal' hostname. Because the ToolHive control plane API and individual MCP proxy endpoints lack authentication, any compromised or malicious MCP server container can reach services listening on the host's localhost. This exposure allows an attacker to interact with the ToolHive API, other ToolHive-managed proxy services, the Kubernetes API, and host-local LLM APIs like Ollama. This flaw enables unauthorized lateral movement and command execution on the host machine without requiring a container escape vulnerability.

## Attack Chain

1. Attacker deploys or compromises a containerized MCP server instance within the ToolHive environment.
2. Attacker performs internal network reconnaissance by scanning 'host.docker.internal' from within the container context.
3. Attacker identifies sensitive services listening on the host, such as the ToolHive control plane (port 50444) or Ollama (port 11434).
4. Attacker initiates an unauthenticated JSON-RPC MCP handshake with the discovered ToolHive control plane or proxy endpoints.
5. Attacker leverages discovered MCP tool capabilities to interact with host resources, such as reading files or executing system commands.
6. Attacker pivots to privileged native MCP tools residing on the host that lack granular access control.
7. Attacker achieves unauthorized host-level actions or data exfiltration based on the permissions of the targeted local service.

## Impact

Successful exploitation allows attackers to perform lateral movement from an isolated container environment to the host system. Impact includes the potential for unauthorized code execution, full exfiltration of data handled by other MCP servers, manipulation of the ToolHive configuration, and unauthorized use of LLM model inference APIs. The vulnerability affects users of the ToolHive desktop application and Docker runtime environments, specifically those running versions prior to 0.30.1.

## Recommendation

1. Upgrade all ToolHive deployments to version 0.30.1 or later to remediate the insecure default container networking settings.
2. Implement strict network policy controls to block 'host.docker.internal' and '172.17.0.1' access for all containerized MCP servers by default.
3. Transition to explicit allow-lists for container network communication within ToolHive permission profiles.
4. Implement authentication mechanisms, such as tokens or mutual TLS, for all inter-service communication between the ToolHive proxy and individual MCP servers.
5. Enable audit logging for all MCP tool calls to improve detection of unauthorized inter-server or host-access attempts.
