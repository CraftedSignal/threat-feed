---
title: Security Control Bypass in Network-AI ClaudeHookBridge
slug: 2026-10-network-ai-bypass
description: Network-AI versions 5.14.0 through 5.15.1 contain a security control bypass in the ClaudeHookBridge PreToolUse hook, enabling prompt-injected agents to execute arbitrary scripts or deploy web shells.
date: "2026-10-12T20:29:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:network-ai:network-ai:5.14.0:*:*:*:*:*:*:*
  - cpe:2.3:a:network-ai:network-ai:5.15.1:*:*:*:*:*:*:*
vendors:
  - Network-AI
products:
  - Network-AI (5.14.0 - 5.15.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A prompt-injected agent can place dangerous payloads in fields like Write content or an MCP script parameter beside a benign file_path or command, evading denyPatterns.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This flaw facilitates the execution of unauthorized scripts or the creation of web shells on the targeted network appliance.
    confidence_band: high
cves:
  - id: CVE-2026-109331
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109331
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Network-AI instances to version 5.15.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states versions before 5.15.2 are vulnerable.
  hunt_leads:
    - lead: Search application logs for requests to the ClaudeHookBridge containing unexpected multi-parameter payloads or script-like content in non-primary fields.
      technique_id: T1190
      data_needed:
        - Application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows malicious payloads in secondary fields.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 5.15.2
      owner: IT Operations
      addresses: CVE-2026-109331
      evidence: NVD vulnerability detail
---

Network-AI versions 5.14.0 through 5.15.1 are vulnerable to a security control bypass flaw identified as CVE-2026-109331 within the ClaudeHookBridge PreToolUse hook. The vulnerability stems from improper input validation logic where the hook only evaluates the first candidate field of a request against established deny patterns. An attacker can leverage this limitation by using prompt injection to craft malicious inputs that hide dangerous payloads, such as web shell content or unauthorized script parameters, in secondary fields while keeping the primary field benign. Successful exploitation of this vulnerability allows an attacker to bypass security filters, leading to arbitrary script execution or unauthorized file modifications on the appliance. Defenders should prioritize patching affected instances to version 5.15.2 or later to address the validation logic flaw.

## Attack Chain

1. Attacker identifies a target running Network-AI (v5.14.0 - 5.15.1).
2. Attacker crafts a prompt injection sequence designed to interact with the ClaudeHookBridge.
3. Attacker constructs a multi-field request where the first field satisfies benign deny-pattern checks.
4. Attacker inserts malicious payload (e.g., shell script or web shell code) into a secondary field like "Write content" or an MCP script parameter.
5. The ClaudeHookBridge PreToolUse hook parses the request and validates only the primary field.
6. The validation logic ignores the secondary field due to the flawed implementation, allowing the malicious request to pass.
7. The system processes the request, executing the script or writing the malicious file to the filesystem.
8. Attacker gains unauthorized persistence or execution on the network appliance.

## Impact

The vulnerability poses a high risk to organizations utilizing Network-AI, as it allows attackers to bypass core security controls meant to limit agent capabilities. If exploited, an attacker could achieve unauthorized code execution, deploy web shells for persistent access, or modify critical system files. This vulnerability affects all environments running the vulnerable software versions, potentially impacting a wide range of deployments that rely on these security hooks for input sanitization.

## Recommendation

* Upgrade Network-AI to version 5.15.2 or later immediately to resolve the validation logic flaw in the ClaudeHookBridge PreToolUse hook.
* Audit logs for anomalous activity involving the ClaudeHookBridge component, focusing on requests where multiple input fields or parameters are present in a single interaction.
* Restrict the deployment of AI agents in production environments to those with validated, secure integration configurations until patching is completed.
