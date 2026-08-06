---
title: Use-After-Free Vulnerability in llama-server
slug: 2026-08-llama-cpp-uaf
description: A use-after-free vulnerability in llama-server allows for potential remote code execution via a TOCTOU race condition in tokenization endpoints when using the --sleep-idle-seconds configuration.
date: "2026-08-06T23:30:34Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - llama.cpp
products:
  - llama-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Exploitation for Credential Access
    evidence: The vulnerability arises from a time-of-check-time-of-use (TOCTOU) race condition where worker threads access the vocabulary after it has been freed by the main thread.
    confidence_band: med
cves:
  - id: CVE-2026-43632
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43632
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade llama-server to build > b9060
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-43632 requires patching for remediation.
  mitigation_plan:
    - priority: immediate
      action: Remove --sleep-idle-seconds flag from server launch arguments
      owner: IT Operations
      addresses: CVE-2026-43632
      evidence: The vulnerability triggers when --sleep-idle-seconds is configured.
---

CVE-2026-43632 is a use-after-free vulnerability affecting llama-server builds b7492 through b9060. The vulnerability resides in the handling of six specific tokenization-related endpoints: /tokenize, /detokenize, /infill, /apply-template, /rerank, and /anthropic/count_tokens. These endpoints bypass the standard task queue and access the 'ctx_server.vocab' memory structure directly from HTTP worker threads.

The issue stems from a time-of-check-time-of-use (TOCTOU) race condition. When the application is configured with the '--sleep-idle-seconds' flag, the main thread can destroy and free the vocabulary memory after the synchronization lock is released but before the HTTP worker thread has finished utilizing the reference. This leads to memory corruption, service crashes, or potential remote code execution if an attacker can reliably trigger the race condition while the server is transitioning into an idle state.

## Impact

Successful exploitation of this vulnerability leads to denial-of-service via application crashes or potential remote code execution on the server hosting the llama-server instance. Given the prevalence of local LLM deployment, this represents a significant risk for organizations using llama-server as a backend component for AI-integrated services or private infrastructure, particularly when exposed to untrusted network traffic.

## Recommendation

* Update llama.cpp to a build version later than b9060 to mitigate CVE-2026-43632.
* Monitor access logs for sustained, high-frequency requests to the identified tokenization endpoints, as these may indicate attempts to win the race condition.
* Disable the '--sleep-idle-seconds' configuration flag in production environments until a patched build is deployed to eliminate the triggering condition for the race.
