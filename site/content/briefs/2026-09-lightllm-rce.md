---
title: Remote Code Execution in LightLLM Config Server via Insecure Deserialization
slug: 2026-09-lightllm-rce
description: LightLLM versions 1.2.0 and earlier are vulnerable to unauthenticated remote code execution via the Config Server's /visual_register WebSocket endpoint due to insecure pickle deserialization.
date: "2026-09-14T13:33:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lightllm:lightllm:*:*:*:*:*:*:*:*
vendors:
  - LightLLM
products:
  - LightLLM (<= 1.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LightLLM through 1.2.0 contains a remote code execution vulnerability in the Config Server's unauthenticated /visual_register WebSocket endpoint
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can reach the Config Server port and send a malicious serialized payload with a __reduce__ method to execute arbitrary code
    confidence_band: high
cves:
  - id: CVE-2026-90919
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90919
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the LightLLM Config Server port to trusted internal ranges only
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated RCE vulnerability in the Config Server component
  mitigation_plan:
    - priority: immediate
      action: Identify all instances of LightLLM 1.2.0 or earlier in the environment
      owner: SOC
      addresses: CVE-2026-90919
      evidence: LightLLM through 1.2.0 contains a remote code execution vulnerability
---

LightLLM versions through 1.2.0 contain a critical remote code execution (RCE) vulnerability in the Config Server component. The vulnerability resides in the /visual_register WebSocket endpoint, which fails to implement any authentication mechanisms. The application insecurely handles client-provided frames by passing the first frame directly to the Python pickle.loads() function. An unauthenticated attacker capable of reaching the Config Server network port can send a maliciously crafted, serialized pickle payload containing a __reduce__ method. Successful exploitation allows the attacker to execute arbitrary code within the context of the Config Server process. Given the nature of pickle-based deserialization vulnerabilities, this flaw poses a high risk to environment integrity, as it grants full execution capabilities to remote, unauthenticated parties.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable Config Server endpoints.
2. Attacker establishes a WebSocket connection to the /visual_register endpoint on the target server.
3. Attacker crafts a malicious Python object payload using the pickle module's __reduce__ method.
4. Attacker sends the serialized binary data as the first frame over the established WebSocket.
5. The Config Server component receives the payload and passes the data to pickle.loads().
6. The Python interpreter deserializes the malicious object, triggering the execution of the embedded instructions.
7. Attacker achieves arbitrary code execution with the permissions of the underlying service account.

## Impact

Successful exploitation of CVE-2026-90919 allows for complete compromise of the affected Config Server process. In enterprise environments, this could lead to lateral movement, data exfiltration, or deployment of further persistence mechanisms. There is currently no mitigation or patch specified; users should restrict network access to the Config Server port.

## Recommendation

Prioritize network segmentation to ensure the LightLLM Config Server port is not accessible from untrusted or external networks. Monitor application logs for unexpected WebSocket connection attempts to the /visual_register URI.
