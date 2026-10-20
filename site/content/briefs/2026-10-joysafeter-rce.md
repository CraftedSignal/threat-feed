---
title: Remote Code Execution in JoySafeter via Unsandboxed Execute Tool
slug: 2026-10-joysafeter-rce
description: JoySafeter version 1.0.0 and earlier contains a remote code execution vulnerability allowing authenticated users to execute shell commands via an unsandboxed agent tool.
date: "2026-10-20T02:31:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:joysafeter:joysafeter:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cloud-security
  - vulnerability
vendors:
  - JoySafeter
products:
  - JoySafeter (<= 1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can self-register, select standard mode in the WebSocket chat.start extension, and have the agent invoke subprocess.run with shell=True on the host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The agent invoke subprocess.run with shell=True on the host to access other tenants data and server secrets.
    confidence_band: high
cves:
  - id: CVE-2026-109443
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109443
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or restrict JoySafeter version 1.0.0 instances
      owner: IT Operations
      due: 48h
      evidence: JoySafeter through 1.0.0 contains a remote code execution vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade JoySafeter to a version greater than 1.0.0
      owner: IT Operations
      addresses: CVE-2026-109443
      evidence: JoySafeter through 1.0.0 contains a remote code execution vulnerability
---

JoySafeter versions 1.0.0 and earlier contain a critical remote code execution (RCE) vulnerability that allows authenticated users to execute arbitrary operating system commands. The vulnerability stems from an unsandboxed 'execute' tool within the platform's Copilot standard mode. Attackers can exploit this by self-registering for an account and initiating a WebSocket connection through the 'chat.start' extension. By selecting 'standard mode' during the chat initiation, the attacker influences the agent to invoke the 'subprocess.run' function with the 'shell=True' parameter. This direct execution on the host server enables unauthorized access to sensitive server secrets and data belonging to other tenants. This vulnerability poses a significant risk to multi-tenant environments where server-side agent execution is exposed without adequate sandboxing.

## Attack Chain

1. Attacker performs self-registration to create a valid user account on the target JoySafeter instance.
2. Attacker initiates a WebSocket connection to the platform's chat interface.
3. Attacker sends a request to the 'chat.start' extension to initialize a new session.
4. Attacker specifies 'standard mode' in the session configuration to leverage the vulnerable agent tool path.
5. Attacker provides input via the chat interface that is processed by the unsandboxed execute tool.
6. The agent backend receives the input and invokes 'subprocess.run' with 'shell=True' on the host operating system.
7. Attacker executes arbitrary OS commands with the privileges of the JoySafeter backend process.
8. Attacker exfiltrates server secrets or crosses tenant boundaries to access restricted data.

## Impact

Successful exploitation allows for full remote code execution on the host server. This leads to complete loss of confidentiality and integrity, as attackers can access server secrets and data across multiple tenants. The vulnerability has a CVSS v3.1 base score of 8.8, reflecting the high potential for compromise in SaaS or multi-tenant deployments.

## Recommendation

- Upgrade JoySafeter to a version greater than 1.0.0 once a patch is available from the vendor.
- Review and restrict permissions for the 'chat.start' extension to prevent unprivileged users from accessing 'standard mode' or the 'execute' tool.
- Monitor backend logs for unauthorized invocations of 'subprocess.run' or shell spawning commands originating from the JoySafeter application process.
- Implement network segmentation to isolate the JoySafeter application server from internal secrets management services.
