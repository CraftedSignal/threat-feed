---
title: Unauthenticated Information Disclosure in @rsdoctor/rspack-plugin
slug: 2026-09-rsdoctor-unauth-api
description: The @rsdoctor/rspack-plugin binds its report server to all network interfaces with no authentication, allowing attackers to exfiltrate source code and build metadata via an unauthenticated POST request.
date: "2026-09-24T20:05:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - supply-chain
  - developer-tools
vendors:
  - Rspack
products:
  - '@rsdoctor/rspack-plugin (<= 1.5.11)'
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592.001
    technique_name: 'Gather Victim Host Information: Hardware'
    evidence: Any network-adjacent or remote attacker can send a single unauthenticated request to retrieve the full source code of all compiled JavaScript modules.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attacker can exfiltrate sensitive build artifacts, including full JavaScript source code... from developer machines.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jmg2-rcxh-w8q3
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade @rsdoctor/rspack-plugin to 1.5.16 or later across all development environments
      owner: Development
      due: 24h
      evidence: Upgrade Path section of the source material
  mitigation_plan:
    - priority: immediate
      action: Configure local firewalls to deny inbound traffic to ports used by Rsdoctor from non-local sources
      owner: IT Operations
      addresses: Network-based exploitation of Rsdoctor server
      evidence: Source details on server binding to 0.0.0.0
---

The `@rsdoctor/rspack-plugin` (up to version 1.5.11) contains a critical information disclosure vulnerability caused by the default behavior of its internal HTTP report server. By default, the server binds to `0.0.0.0` (all network interfaces) and enables a `POST /api/data/key` endpoint without any authentication mechanism. Furthermore, the SDK applies a wildcard CORS policy, allowing cross-origin requests from any source. 

When a developer runs a build using this plugin, the server starts automatically in non-CI environments. Any network-adjacent attacker can perform a single unauthenticated HTTP POST request to this server to retrieve sensitive build artifacts, including the full JavaScript source code of all compiled modules (`moduleCodeMap`), absolute file paths, and build configuration details (`configs`). This vulnerability is particularly dangerous for developers on shared networks, VPNs, or those running the plugin in environments accessible via local networks. The vulnerability is resolved in version 1.5.16, which mandates binding to `127.0.0.1` and restricts CORS origins.

## Attack Chain

1. Attacker identifies a target developer machine running a build process with `@rsdoctor/rspack-plugin` on a shared network (e.g., VPN or local Wi-Fi).
2. The Rsdoctor SDK server initializes and binds to `0.0.0.0` on a dynamic port, making it reachable by any device on the local network.
3. Attacker discovers the active port via network scanning or by observing traffic from the target device.
4. Attacker sends a malicious, unauthenticated HTTP POST request to `http://<victim-lan-ip>:<port>/api/data/key`.
5. The server's `loadDataByKey` method accepts the user-supplied `key` from the request body without validation or authentication.
6. The `base.ts` handler uses the attacker-controlled `key` to index the internal SDK data store, including traversal of nested keys.
7. The system serializes the requested sensitive data (e.g., `moduleCodeMap`) and returns the full content of the source code or build configuration to the attacker.
8. The attacker parses the JSON response to harvest proprietary source code, credentials, or file structure information.

## Impact

Successful exploitation leads to the complete disclosure of project source code and build environment metadata. This includes hardcoded API keys, proprietary business logic, absolute filesystem paths, and environment variables contained within the build process. Impacted parties include individual developers and enterprise organizations where developers run local builds on semi-trusted or shared networks.

## Recommendation

- Upgrade `@rsdoctor/rspack-plugin` to version 1.5.16 or later immediately.
- Implement network segmentation to ensure build processes on developer machines are not reachable by unauthorized devices on the local network.
- Audit developer workstations for rogue HTTP services running on all interfaces (0.0.0.0) that lack authentication.
- Use firewall rules to restrict inbound connections to build-related ports to `localhost` (127.0.0.1) until all projects are patched.
