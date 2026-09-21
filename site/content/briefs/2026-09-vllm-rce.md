---
title: Remote Code Execution in vLLM LlavaOnevision2 Processor Loader
slug: 2026-09-vllm-rce
description: A vulnerability in vLLM versions prior to 0.28.0 allows remote code execution by bypassing the trust_remote_code parameter during the loading of malicious LlavaOnevision2 processor classes.
date: "2026-09-12T13:20:03Z"
lastmod: "2026-09-21T22:31:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - model-inference
  - supply-chain
  - denial-of-service
  - vllm
  - vulnerability
vendors:
  - vLLM
products:
  - vLLM (< 0.28.0)
  - vLLM (< 0.28.0)
  - vLLM (<= 0.29.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: vLLM before 0.28.0 contains a remote code execution vulnerability in the LlavaOnevision2 processor loader that ignores the trust_remote_code parameter when loading remote processor classes.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Remote attackers can submit requests with max_tokens=0 to exhaust decode-worker memory without bound until the worker restarts.
    confidence_band: high
cves:
  - id: CVE-2026-90553
    cvss: 7.8
    epss: 0.00207
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90553
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3327
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93436
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93592
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94623
rules:
  - title: Detect CVE-2026-93592 Exploitation - Negative Token ID in vLLM API Request
    description: Detects HTTP requests to vLLM embedding or pooling endpoints containing negative integer values in the token IDs parameter, indicative of CVE-2026-93592 exploitation.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade vLLM to version 0.28.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90553 patch availability in vLLM 0.28.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vLLM to version 0.28.0 or later.
      owner: IT Operations
      addresses: CVE-2026-90553
      evidence: NVD vulnerability remediation guidance.
updates:
  - at: "2026-09-14T13:03:57Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3327
  - at: "2026-09-18T00:04:27Z"
    level: L1
    summary: added coverage for vLLM (<= 0.29.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93436
  - at: "2026-09-18T16:07:31Z"
    level: L1
    summary: 'added detection rule: Detect CVE-2026-93592 Exploitation - Negative Token ID in vLLM API Request'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93592
  - at: "2026-09-21T22:31:04Z"
    level: L1
    summary: added coverage for vLLM (<= 0.29.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94623
---

vLLM versions prior to 0.28.0 are susceptible to a high-severity remote code execution vulnerability (CVE-2026-90553) located within the LlavaOnevision2 processor loader. The vulnerability stems from a flaw in the loader logic that fails to respect the trust_remote_code configuration parameter when initializing remote processor classes. Under normal security configurations, setting trust_remote_code to False is intended to prevent the execution of arbitrary code from model repositories. However, in this implementation, the loader ignores this directive, enabling attackers to include malicious Python code within a crafted processing_llava_onevision2.py file inside a model. When the vLLM application attempts to load the malicious model, the embedded code executes with the privileges of the vLLM process. This flaw significantly impacts organizations deploying vLLM for model serving, as it allows arbitrary code execution even when users follow established security best practices.

## Impact

Successful exploitation results in full remote code execution within the environment running the vLLM process. This allows attackers to gain unauthorized access to the host, steal data, or pivot further into the internal network. The vulnerability affects all users and organizations utilizing vLLM for machine learning model inference who have not yet upgraded to version 0.28.0.

## Recommendation

1. Upgrade all vLLM deployments to version 0.28.0 or later immediately to patch CVE-2026-90553.
2. Implement strict access controls for model storage locations to prevent unauthorized modification of model files, including the processing_llava_onevision2.py script.
3. Run vLLM processes in isolated environments, such as containers or dedicated VMs with restricted filesystem and network access, to minimize the impact of potential RCE.
4. Perform integrity checks on model repositories before loading them into the vLLM inference engine.
