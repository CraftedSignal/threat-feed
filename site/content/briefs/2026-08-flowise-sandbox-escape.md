---
title: Flowise Sandbox Escape to Remote Code Execution
slug: 2026-08-flowise-sandbox-escape
description: Authenticated attackers can exploit an insecure JavaScript sandbox configuration in FlowiseAI to execute arbitrary system commands via a chained injection and path traversal payload.
date: "2026-08-04T17:24:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:momentjs:moment:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:momentjs:moment:*:*:*:*:*:nuget:*:*
  - cpe:2.3:a:tenable:tenable.sc:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq:-:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
vendors:
  - FlowiseAI
products:
  - Flowise (3.1.1)
  - nodevm (3.9.25)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following script is a reverse shell payload that connects to 172.17.0.1:1337 that had a filename of rce.js.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: |-
      An attacker could inject arbitrary code by inserting #";
      {malicious_code};// at the end of the baseURL setting.
    confidence_band: high
cves:
  - id: CVE-2022-24785
    cvss: 7.5
    epss: 0.0552
references:
  - https://github.com/advisories/GHSA-wg86-r78f-74mp
  - https://nvd.nist.gov/vuln/detail/CVE-2022-24785
---

FlowiseAI is vulnerable to a sandbox escape that allows authenticated attackers to achieve Remote Code Execution (RCE). The platform utilizes the `patriksimek/vm2` library (via the `nodevm` module) to execute custom user-provided JavaScript code. Despite the library being deprecated due to inherent security flaws, several Flowise components, such as `AgentAsTool`, continue to invoke this sandbox with `useSandbox: false` or in insecure configurations.

The vulnerability stems from an injection point within the `baseURL` parameter of the `AgentAsTool` node. An attacker can bypass the `isValidURL` validation function using a hash fragment injection. This is chained with a sandbox escape that leverages a known path traversal flaw in the `moment` library (`CVE-2022-24785`). By forcing the `moment` library to load a malicious file, the attacker can break out of the Node.js sandbox and execute arbitrary commands on the underlying host. The issue persists in Flowise version 3.1.1 and impacts the `nodevm` package version 3.9.25.

## Attack Chain

1. The attacker authenticates to the target Flowise instance and retrieves a valid organization ID and session cookies.
2. The attacker uses the platform's document loader to upload a malicious JavaScript payload (e.g., a reverse shell) as a file (e.g., `rce.js`) to the application server.
3. The attacker initiates an `AgentAsTool` or similar node configuration within the Flowise workflow interface.
4. The attacker crafts a malicious `baseURL` input string containing a hash fragment injection, such as `#";\nfake = new String(".../tmp/rce.js"); ... //`.
5. The `AgentAsTool` component fails to sanitize the injected string due to the broken `isValidURL` implementation and inserts the payload into the sandboxed execution context.
6. The `vm2` sandbox executes the injected code, which triggers the `moment.locale()` bypass to traverse the filesystem and access the uploaded `rce.js` file.
7. The `child_process` module is invoked within the context of the Node.js process to execute the payload.
8. The final objective is achieved via a reverse shell or arbitrary code execution on the host system.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary commands on the server hosting the Flowise instance. This leads to full system compromise, potential data exfiltration of internal workflows, and unauthorized access to infrastructure-level resources. Given that Flowise is often used to manage AI agents and sensitive API keys, the impact includes lateral movement within the network and potential compromise of connected third-party SaaS services.

## Recommendation

* Upgrade Flowise to a version where all components explicitly enforce the use of secure, containerized sandboxing (e.g., E2B) rather than the deprecated `vm2` library.
* Audit all code paths utilizing `useSandbox: false` in Flowise components (specifically `AgentAsTool`, `ChatflowTool`, and `ExecuteFlow`) and transition them to secure isolation mechanisms.
* Implement strict input validation for URL fields, ensuring that hash fragments and newline characters are sanitized before being processed in dynamic code generation.
* Restrict the `node-fetch` and `moment` dependency access within the sandbox environment to prevent access to the local filesystem.
* Monitor internal network traffic for unexpected outbound connections from the server hosting Flowise, specifically targeting ports associated with command-and-control (C2) activity (e.g., `nc` reverse shells).
