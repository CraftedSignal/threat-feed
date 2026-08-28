---
title: SSRF Vulnerability in Qwen-Agent Document Parsing
slug: 2026-08-qwen-agent-ssrf
description: Qwen-Agent version 0.0.34 and earlier contains a server-side request forgery (SSRF) vulnerability that allows unauthenticated attackers to force the server to perform arbitrary internal HTTP requests and exfiltrate metadata service content.
date: "2026-08-28T21:38:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:alibaba:qwen-agent:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - cloud
vendors:
  - Alibaba
products:
  - Qwen-Agent (<= 0.0.34)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can reach the unauthenticated Gradio interface to make the server issue HTTP requests to arbitrary internal addresses including metadata services and read retrieved content through parsed document output.
    confidence_band: high
cves:
  - id: CVE-2026-82268
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82268
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review and restrict outbound network access from servers hosting Qwen-Agent to internal metadata endpoints.
      owner: Security Engineering
      due: 24h
      evidence: Source notes risk to metadata services.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Qwen-Agent to a patched version once released by the vendor.
      owner: IT Operations
      addresses: CVE-2026-82268
      evidence: Source identifies vulnerability in versions <= 0.0.34.
---

Qwen-Agent, an open-source agent framework, contains a server-side request forgery (SSRF) vulnerability identified as CVE-2026-82268 affecting versions through 0.0.34. The flaw exists within the document parsing functionality, which fails to adequately validate or restrict caller-supplied paths. Specifically, the application processes these paths as URLs without enforcing scheme restrictions or host validation. An unauthenticated attacker can exploit this behavior by manipulating the document parsing input to interact with the server's local environment, including internal Gradio interfaces or cloud-provider metadata services. This enables the attacker to force the server to issue arbitrary HTTP requests and potentially read returned data, which is subsequently surfaced through the application's document parsing output. This vulnerability presents a high risk for environments where Qwen-Agent is deployed with access to internal network resources or sensitive cloud service endpoints.

## Impact

Successful exploitation allows unauthenticated attackers to bypass network boundaries and interact with internal services that are not exposed to the public internet. This can lead to the exfiltration of sensitive information, such as cloud metadata, internal configuration details, or credentials, which may facilitate further compromise of the underlying infrastructure or internal services.

## Recommendation

* Upgrade to a version of Qwen-Agent that addresses CVE-2026-82268 once available.
* Restrict network access for servers hosting Qwen-Agent to prevent them from reaching internal metadata services (e.g., 169.254.169.254) or sensitive administrative endpoints.
* Implement strict input validation on all document parsing paths to ensure only expected URLs or local file paths are processed.
