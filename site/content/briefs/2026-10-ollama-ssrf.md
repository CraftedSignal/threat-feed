---
title: Ollama SSRF Vulnerability (CVE-2026-108836)
slug: 2026-10-ollama-ssrf
description: Ollama versions up to 0.34.1 contain a Server-Side Request Forgery (SSRF) vulnerability in the Pull API component allowing remote attackers to perform unauthorized internal requests.
date: "2026-10-12T13:43:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - ollama
vendors:
  - Ollama
products:
  - Ollama (<= 0.34.1)
cves:
  - id: CVE-2026-108836
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108836
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Ollama to version 0.34.2
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 0.34.2 is sufficient to fix this issue.
  mitigation_plan:
    - priority: immediate
      action: Update Ollama to 0.34.2
      owner: IT Operations
      addresses: CVE-2026-108836
      evidence: Upgrading to version 0.34.2 is sufficient to fix this issue.
---

A server-side request forgery (SSRF) vulnerability, assigned CVE-2026-108836, has been identified in the Pull API component of Ollama. The flaw resides in the IsValid function located within types/model/name.go. An attacker can exploit this vulnerability remotely by supplying specially crafted inputs to the Pull API, forcing the Ollama server to make unauthorized HTTP requests to arbitrary internal or external endpoints. This could allow an attacker to bypass firewalls, probe internal network services, or exfiltrate sensitive data accessible to the server. The vulnerability affects all versions of Ollama up to and including 0.34.1. This vulnerability is documented as publicly disclosed, and attackers may leverage this to gain further access to internal environments. Organizations are advised to update their Ollama instances to version 0.34.2 or later to mitigate this risk.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to perform SSRF attacks, which can lead to unauthorized access to internal resources, metadata services, or sensitive internal APIs. This poses a significant risk to organizations running Ollama in environments where the server has access to internal network segments or cloud metadata endpoints. There are no specific numbers of victims provided, but the widespread use of Ollama for local LLM deployment makes this a high-impact risk for development and infrastructure environments.

## Recommendation

- Upgrade all Ollama instances to version 0.34.2 or later immediately.
- Patch dfabde4539e42ba1e1eab50a3a50b88aea7958a0 is the specific fix for this issue in the codebase.
- Implement network egress filtering on servers hosting Ollama to prevent the service from reaching unauthorized internal network segments.
