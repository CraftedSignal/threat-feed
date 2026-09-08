---
title: Remote Code Execution via CORS Misconfiguration in winml-cli
slug: 2026-09-winml-rce
description: An unauthenticated RCE vulnerability in winml-cli (CVE-2026-84452) allows remote attackers to execute arbitrary code via a malicious website sending cross-origin requests to the local API server.
date: "2026-09-08T21:49:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:winml-cli:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - cors
vendors:
  - Microsoft
products:
  - winml-cli (< 0.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: The attacker lures the victim to a website that sends a request to the local API server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker forces execution of arbitrary Python code embedded within a malicious model repository.
    confidence_band: high
cves:
  - id: CVE-2026-84452
    epss: 0.00945
references:
  - https://github.com/advisories/GHSA-96p9-rh4f-92cf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84452
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade winml-cli to 0.4.0 or higher
      owner: IT Operations
      due: 48h
      evidence: Source advisory states 0.4.0 resolves the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade winml-cli to 0.4.0
      owner: IT Operations
      addresses: CVE-2026-84452
      evidence: GHSA-96p9-rh4f-92cf
---

The 'winml-cli' project contains a critical security vulnerability (CVE-2026-84452) in its 'serve/cli_api.py' component that facilitates Remote Code Execution (RCE). The tool launches a local HTTP API server that binds to 127.0.0.1 by default; however, it incorrectly configures Cross-Origin Resource Sharing (CORS) by setting 'allow_origins' to a wildcard ('*'). This configuration allows any website visited by the user to send requests to the local winml-cli instance, effectively bypassing the intended localhost-only network boundary.

Furthermore, the API exposes 'build' and 'config' commands that accept the '--trust-remote-code' parameter. By injecting this parameter through a crafted cross-origin request, an attacker can force the application to load a malicious model repository. The underlying 'transformers' library then imports Python code from the repository, leading to immediate code execution under the context of the user running the CLI server. This vulnerability affects versions of 'winml-cli' prior to 0.4.0.

## Attack Chain

1. The victim starts the winml-cli HTTP API server locally using 'python -m uvicorn winml.modelkit.serve.cli_api:app'.
2. An attacker hosts a malicious model repository containing a 'configuration_pwn.py' file with embedded Python code.
3. The victim is lured to an attacker-controlled website that contains malicious JavaScript.
4. The JavaScript sends a cross-origin POST request to 'http://127.0.0.1:8000/v1/cli/build' due to the overly permissive CORS wildcard.
5. The request includes JSON data setting 'trust_remote_code' to 'true' and pointing the 'model' argument to the attacker-controlled model repository.
6. The 'winml-cli' server processes the request and executes 'AutoConfig.from_pretrained' with the 'trust_remote_code=True' flag.
7. The 'transformers' library imports the malicious module from the remote repository, triggering the embedded arbitrary code execution.

## Impact

Successful exploitation results in full Remote Code Execution (RCE) on the victim's machine under the privileges of the user running the winml-cli process. This can lead to local data exfiltration, installation of persistent backdoors, or lateral movement within the user's environment. This vulnerability primarily impacts developers and data scientists using winml-cli in local development workflows.

## Recommendation

1. Upgrade 'winml-cli' to version 0.4.0 or later immediately to resolve the CORS misconfiguration and the unsafe handling of 'trust_remote_code'.
2. Implement local firewall rules to restrict traffic to the port used by the winml-cli API (default 8000) to explicitly trusted processes if feasible.
3. Avoid running the winml-cli server while browsing untrusted websites.
4. Deploy network-level protections to alert on unexpected POST requests to 'http://127.0.0.1:8000' originating from web browser processes.
