---
title: Remote Code Execution in LMDeploy via Unsafe Pickle Deserialization
slug: 2026-08-lmdeploy-pickle-rce
description: The LMDeploy library insecurely deserializes untrusted peer-to-peer messages using Python's pickle module, allowing unauthenticated remote attackers to achieve remote code execution by providing a malicious ZMQ endpoint.
date: "2026-08-19T22:39:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - LMDeploy
products:
  - LMDeploy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The POST /distserve/p2p_initialize and /distserve/p2p_connect endpoints in lmdeploy/serve/openai/api_server.py apply no authentication unless the server is started with api_keys.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: The handle_zmq_recv coroutine in lmdeploy/pytorch/disagg/conn/engine_conn.py reads peer-to-peer cache-free requests with recv_pyobj(), which deserializes the received bytes with pickle.loads().
    confidence_band: high
cves:
  - id: CVE-2026-76850
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76850
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to API ports for LMDeploy deployments
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated RCE via API endpoints
  mitigation_plan:
    - priority: immediate
      action: Enable mandatory API key authentication for LMDeploy server
      owner: IT Operations
      addresses: CVE-2026-76850
      evidence: Source states authentication defaults to None unless enabled
---

LMDeploy is vulnerable to remote code execution (CVE-2026-76850) due to unsafe deserialization practices within its disaggregated serving component. The issue resides in the handle_zmq_recv coroutine, which utilizes the recv_pyobj() method to process peer-to-peer cache-free requests. This method inherently relies on pickle.loads() to deserialize incoming bytes. Crucially, the validation check against the expected object type (DistServeCacheFreeRequest) occurs only after the deserialization process is complete. 

An unauthenticated remote attacker can exploit this by interacting with the /distserve/p2p_initialize or /distserve/p2p_connect endpoints in the OpenAI-compatible API server. Since authentication is disabled by default, an attacker can manipulate the ZMQ address parameter, forcing the victim engine to connect to an attacker-controlled ZMQ PULL socket. The attacker then provides a serialized pickle payload, which is executed within the engine process upon receipt. This vulnerability only impacts deployments where disaggregated serving is actively configured and utilized.

## Impact

Successful exploitation results in full remote code execution within the context of the LMDeploy engine process. This allows an attacker to compromise the underlying host, access sensitive model data, exfiltrate environment variables, or persist within the infrastructure supporting the LLM serving environment. The severity is CVSS 9.8 (Critical), reflecting the ease of exploitability and the potential for complete system takeover.

## Recommendation

- Immediately disable the disaggregated serving feature if it is not strictly required for current operations.
- If disaggregated serving is required, enforce API key authentication by configuring the LMDeploy server to require authentication keys, ensuring the default None value is overridden.
- Implement network-level segmentation to restrict access to the /distserve/* API endpoints to known, trusted internal peers only.
- Audit LMDeploy configuration files to ensure that remote endpoints are not accepting input from untrusted ZMQ sources.
