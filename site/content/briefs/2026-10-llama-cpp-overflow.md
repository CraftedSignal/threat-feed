---
brief_id: brief-2026-10-28-llama-cpp-overflow
event_id: brief-2026-10-28-llama-cpp-overflow
revision: 1
activity_at: "2026-10-28T04:39:18Z"
title: 'llama.cpp: Unauthenticated remote code execution in ggml-rpc RDMA transport (CVE-2026-118375)'
slug: 2026-10-llama-cpp-overflow
description: An unauthenticated stack-based buffer overflow vulnerability in the ggml-rpc RDMA transport of llama.cpp versions prior to b11865 allows remote code execution via a malicious RDMA HELLO message.
date: "2026-10-28T04:39:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-118375 release notes and VulnCheck advisory.
cpes:
  - cpe:2.3:a:ggml-org:llama.cpp:*:*:*:*:*:*:*:*
vendors:
  - ggml-org
products:
  - llama.cpp (< b11865)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Unauthenticated stack-based buffer overflow in llama.cpp ggml-rpc RDMA rdma_recv() allows RCE.
    confidence_band: high
cves:
  - id: CVE-2026-118375
    cvss: 8.1
    kev_status: "false"
references:
  - https://github.com/ggml-org/llama.cpp/releases/tag/b11865
  - https://www.vulncheck.com/advisories/llama-cpp-b8841-before-b11865-stack-based-buffer-overflow-via-ggml-rpc-rdma-rdma-recv
  - https://github.com/ggml-org/llama.cpp/pull/30399
  - https://sploitus.com/exploit?id=CVE-2026-118375&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade llama.cpp to version b11865 or later
      owner: IT Operations
      due: 24h
      evidence: Source states b11865 as the fixed version.
  hunt_leads:
    - lead: Identify and baseline network connections to llama.cpp RPC services
      technique_id: T1210
      data_needed:
        - Network connection logs for the llama.cpp RPC port
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is triggered by remote RDMA HELLO messages.
  mitigation_plan:
    - priority: immediate
      action: Disable RDMA functionality in ggml-rpc configuration
      owner: IT Operations
      addresses: CVE-2026-118375
      evidence: Vulnerability is specific to the ggml-rpc RDMA transport layer.
---

A stack-based buffer overflow exists in the `rdma_recv()` function of the `ggml-rpc` RDMA transport in `llama.cpp` versions prior to b11865. The vulnerability occurs because the `rpc_serve_client()` function fails to safely handle data when an attacker advertises RDMA capabilities within a crafted HELLO message. An unauthenticated remote attacker can overflow a 1-byte stack variable with up to 256 KiB of data, leading to a service crash or potential remote code execution.

## Impact

Successful exploitation allows for unauthenticated remote code execution in the context of the `llama.cpp` service, or service denial via application crash.

## Recommendation

* Patch `llama.cpp` by updating to version b11865 or later immediately.
* Disable RDMA capabilities for the `ggml-rpc` service if network transport is not required in your environment.
* Audit network logs for connections to the `llama.cpp` RPC port originating from untrusted network segments.
