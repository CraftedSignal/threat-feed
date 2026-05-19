---
title: Unpatched ChromaDB Vulnerability CVE-2026-45829 Allows Remote Code Execution
slug: 2026-05-chromadb-rce
description: An unpatched pre-authentication remote code execution (RCE) vulnerability, tracked as CVE-2026-45829 and referred to as ChromaToast, in ChromaDB versions 1.0.0 and later allows remote, unauthenticated attackers to execute arbitrary code and leak sensitive information, potentially leading to a server takeover.
date: "2026-05-19T12:55:45Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - chromadb
  - rce
  - cve-2026-45829
  - huggingface
  - vectordatabase
vendors:
  - Chroma
products:
  - ChromaDB >= 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-45829
references:
  - https://www.securityweek.com/unpatched-chromadb-vulnerability-can-lead-to-server-takeover/
  - CVE-2026-45829
rules:
  - title: Detect CVE-2026-45829 Exploitation Attempt - Suspicious HuggingFace Model Download
    description: Detects CVE-2026-45829 exploitation attempt — Monitors network connections for ChromaDB servers downloading models from HuggingFace before authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-45829 Exploitation Attempt - Pre-Authentication Connection to HuggingFace
    description: Detects CVE-2026-45829 exploitation attempt — Identifies ChromaDB processes initiating network connections to HuggingFace infrastructure before user authentication events.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical unpatched vulnerability, CVE-2026-45829 (ChromaToast), exists in ChromaDB, an open-source vector database used in AI applications. This pre-authentication remote code execution (RCE) flaw affects versions 1.0.0 and later. The vulnerability stems from the server's trust in client-supplied model identifiers without proper authentication. An attacker can exploit this by providing a malicious HuggingFace model, which the server executes before conducting authentication checks. This allows the attacker to gain full control of the server process and access sensitive information, including API keys, environment variables, mounted secrets, and all files on the disk. Approximately 73% of internet-accessible ChromaDB deployments are estimated to be affected, with high-profile organizations like Mintlify, Factory AI, and Weights & Biases potentially at risk. This flaw was reported as early as November 2025, but remains unpatched as of ChromaDB version 1.5.8.

## Attack Chain

1. An unauthenticated attacker sends a malicious collection creation request to the ChromaDB server.
2. The request includes a crafted HuggingFace model identifier.
3. The ChromaDB server, without proper authentication, reaches out to HuggingFace.
4. The server downloads the attacker-controlled HuggingFace model.
5. The server executes the downloaded model.
6. This execution occurs before the server performs any authentication checks.
7. The attacker gains full control of the server process due to the RCE vulnerability.
8. The attacker can then access sensitive data, including API keys, environment variables, secrets, and files.

## Impact

Successful exploitation of CVE-2026-45829 grants an unauthenticated attacker complete control over the ChromaDB server process. This allows the attacker to steal sensitive data such as API keys, environment variables, and other secrets stored on the server. The attacker can also access all files on the disk, potentially leading to data breaches and further compromise of the affected systems. With an estimated 73% of internet-accessible ChromaDB deployments vulnerable, this poses a significant risk to organizations using ChromaDB, especially those with default configurations.

## Recommendation

*   Restrict network access to ChromaDB to trusted clients only to mitigate the vulnerability, as suggested by HiddenLayer.
*   Apply the suggested remediation in the code: move the authentication check before configuration loading and stripping any keys named ‘kwargs’ from requests in both the V1 and V2 create_collection handles. This is mentioned in the overview.
*   Monitor network connections to ChromaDB servers for suspicious activity originating from untrusted sources.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
