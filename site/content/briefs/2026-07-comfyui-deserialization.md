---
title: Unauthenticated Remote Code Execution in ComfyUI via Unsafe Deserialization
slug: 2026-07-comfyui-deserialization
description: ComfyUI version 0.23.0 is vulnerable to unauthenticated remote code execution via unsafe deserialization of malicious pickle files.
date: "2026-07-31T23:46:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - deserialization
  - cve-2026-68771
vendors:
  - ComfyUI
products:
  - ComfyUI (0.23.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An unauthenticated attacker can upload a malicious file via the /upload/image endpoint and trigger the execution of arbitrary Python code by queuing a workflow via the /prompt endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The LoadTrainingDataset node... allows unauthenticated remote attackers to execute arbitrary Python code by uploading a crafted pickle file and triggering its deserialization.
    confidence_band: high
cves:
  - id: CVE-2026-68771
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68771
rules:
  - title: Detects CVE-2026-68771 Exploitation - Unauthorized Pickle Upload and Prompting
    description: Detects exploitation of CVE-2026-68771 by identifying sequential POST requests to /upload/image and /prompt in webserver logs, indicative of loading a malicious pickle dataset.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
---

ComfyUI version 0.23.0 contains a critical vulnerability (CVE-2026-68771) within the LoadTrainingDataset node, stemming from the unsafe deserialization of pickle files. This flaw allows an unauthenticated remote attacker to execute arbitrary Python code on the host system. The attack vector involves uploading a crafted, malicious pickle file (typically named in the shard_*.pkl format) via the application's file upload interface. Once the file is hosted, the attacker triggers its deserialization by queuing a workflow graph that references the malicious file. Because the application utilizes the torch.load function to process these files, an attacker can leverage the pickle protocol's __reduce__ method to execute arbitrary system commands under the security context of the ComfyUI process. This vulnerability poses a significant risk to any publicly accessible ComfyUI instance, as it requires no prior authentication to achieve full system compromise.

## Attack Chain

1. Attacker identifies a publicly accessible ComfyUI instance running version 0.23.0.
2. Attacker crafts a malicious Python pickle file containing a __reduce__ method designed to execute arbitrary OS commands.
3. Attacker sends an unauthenticated HTTP POST request to the /upload/image endpoint to store the malicious pickle file on the server.
4. Attacker constructs a JSON workflow graph referencing the path of the newly uploaded malicious file.
5. Attacker sends an unauthenticated HTTP POST request to the /prompt endpoint to submit the workflow graph for processing.
6. The LoadTrainingDataset node within the ComfyUI backend processes the workflow and calls torch.load on the malicious file.
7. The pickle deserialization occurs, triggering the execution of the attacker's payload.
8. The attacker achieves remote code execution, enabling further activity such as data exfiltration or persistence.

## Impact

Successful exploitation results in full remote code execution on the underlying server. This enables attackers to steal sensitive data, gain persistent access to the host, or leverage the compromised system to perform further attacks on the internal network. Given the typical deployment of ComfyUI in AI and research environments, this may lead to the exposure of proprietary model data or credentials.

## Recommendation

1. Immediately update ComfyUI to a patched version that sanitizes or restricts the loading of untrusted pickle files.
2. If an immediate update is not possible, restrict network access to the ComfyUI web interface, ensuring it is not accessible from the public internet.
3. Implement network-level blocking for unauthorized POST requests directed at the /upload/image and /prompt endpoints.
4. Monitor web server logs for suspicious POST requests to /upload/image followed by calls to /prompt containing references to .pkl files.
5. Deploy the Sigma rules provided in this brief to detect the exploitation of CVE-2026-68771.
