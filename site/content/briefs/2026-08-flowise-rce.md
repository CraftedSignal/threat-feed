---
title: Flowise Remote Code Execution via Sandbox Escape
slug: 2026-08-flowise-rce
description: Authenticated users can achieve remote code execution in Flowise by exploiting an insecure object merge in the executeJavaScriptCode function to override sandbox restrictions.
date: "2026-08-04T17:24:08Z"
lastmod: "2026-08-04T19:33:07Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
tags:
  - rce
  - sandbox-escape
  - nodejs
  - flowise
vendors:
  - FlowiseAI
products:
  - Flowise
  - Flowise (<= 3.1.2)
  - flowise-components (<= 3.1.2)
affected_os:
  - Ubuntu 25.10
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The executeJavaScriptCode() function allows the execution of arbitrary JavaScript code inside a NodeVM sandbox which can be leveraged to achieve RCE.
    confidence_band: high
cves:
  - id: CVE-2026-70477
references:
  - https://github.com/advisories/GHSA-3769-jgqc-cxm7
  - https://github.com/advisories/GHSA-5xvg-pmgg-3mxr
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch Flowise instance to version containing fix for GHSA-3769-jgqc-cxm7
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends updating to patched version
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/v1/node-custom-function
      owner: IT Operations
      addresses: Sandbox escape and unauthorized function execution
      evidence: Exploit requires interaction with this specific endpoint
updates:
  - at: "2026-08-04T19:33:07Z"
    level: L2
    summary: poc_available; added CVE-2026-70477; flowise version <= 3.1.2; OS ubuntu 25.10
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-5xvg-pmgg-3mxr
---

Flowise is susceptible to a high-severity sandbox escape vulnerability that allows unauthenticated or authenticated users (depending on deployment configuration) to execute arbitrary code with the privileges of the Flowise process. The vulnerability exists within the `executeJavaScriptCode()` utility, which employs an insecure merge strategy when initializing the NodeVM sandbox. Specifically, the application uses the JavaScript spread operator (`{ ...defaultNodeVMOptions, ...nodeVMOptions }`) to combine default security settings with user-supplied options. Because the user-supplied options are applied last, an attacker can override the restricted `require.builtin` allowlist, re-enabling access to powerful Node.js modules such as `child_process` and `fs`. By bypassing the module restrictions, an attacker can instantiate a nested VM or directly interact with the host filesystem and OS, leading to full system compromise.

## Attack Chain

1. Attacker authenticates to the Flowise API to obtain a valid Bearer token.
2. Attacker interacts with the `/api/v1/node-custom-function` endpoint.
3. Attacker submits a payload containing a malicious `javascriptFunction` string.
4. The Flowise backend controller passes the user-supplied JavaScript code into the `executeCustomNodeFunction` service.
5. The application invokes `executeJavaScriptCode()`, which initializes a NodeVM instance.
6. The attacker uses an absolute path to require internal Flowise utility modules, bypassing existing module resolution restrictions.
7. The attacker calls `executeJavaScriptCode()` again from within the sandbox, providing a malicious `nodeVMOptions` object.
8. The `finalNodeVMOptions` object is constructed, overriding the default sandbox security constraints with `{ require: { builtin: ["*"] } }`.
9. The attacker executes arbitrary OS commands via the `child_process` module, gaining RCE on the server.

## Impact

Successful exploitation results in full remote code execution on the server hosting the Flowise instance. If the Flowise application is running with root or elevated service account privileges, the attacker gains complete control over the host environment. This allows for data exfiltration, lateral movement within the network, and the deployment of persistent threats. All Flowise instances utilizing `executeJavaScriptCode()` are affected.

## Recommendation

* Update Flowise to the latest patched version provided by FlowiseAI that remediates the insecure object spread in `executeJavaScriptCode()`.
* Implement strict network egress filtering for the container or server running Flowise to prevent the execution of malicious payloads that require outbound C2 communication.
* Review and restrict access to the `/api/v1/node-custom-function` endpoint using an identity-aware proxy or firewall, ensuring only trusted administrative users can access this functionality.
* Run the Flowise service with a non-privileged, dedicated service account to limit the impact of potential RCE vulnerabilities.
