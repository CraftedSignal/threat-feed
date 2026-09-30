---
title: Remote Code Execution Vulnerability in Ollama
slug: 2026-09-ollama-rce
description: A vulnerability in Ollama (CVE-2024-37032) allows a remote, unauthenticated attacker to execute arbitrary code via insufficiently validated API requests.
date: "2026-09-30T16:26:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - cve-2024-37032
vendors:
  - Ollama
products:
  - Ollama (< 0.1.34)
cves:
  - id: CVE-2024-37032
    cvss: 8.8
    epss: 0.89633
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3634
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37032
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Ollama to version 0.1.34 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version upgrade for CVE-2024-37032
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Ollama API port 11434
      owner: Security Operations
      addresses: CVE-2024-37032
      evidence: Reducing surface area prevents exploitation of unauthenticated API
---

The Ollama service, a popular tool for running large language models, contains a critical vulnerability (CVE-2024-37032) that permits remote, unauthenticated attackers to achieve code execution on the host machine. This flaw arises from improper validation of incoming API requests, allowing an attacker to inject and execute arbitrary payloads. The vulnerability affects versions of Ollama prior to 0.1.34. As Ollama is frequently deployed to host model inference services that may be exposed to internal networks, this poses a significant risk to the underlying host operating system and any sensitive data within the environment. Defenders should prioritize updating instances of Ollama to version 0.1.34 or later to mitigate this risk.

## Impact

Successful exploitation of CVE-2024-37032 allows an attacker to gain remote command execution on the host running the Ollama service. This can lead to full system compromise, exfiltration of sensitive data, or lateral movement within the network. Users of Ollama across all supported operating systems, including Linux, Windows, and macOS, are impacted if running vulnerable versions.

## Recommendation

* Upgrade all Ollama instances to version 0.1.34 or later to address CVE-2024-37032.
* Audit Ollama service network exposure and implement access control lists (ACLs) to restrict access to the API port, typically 11434, to trusted IP addresses only.
* Use host-based firewall rules to prevent unauthorized external access to the Ollama API interface.
