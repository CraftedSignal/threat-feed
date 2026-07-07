---
title: Coder AI Bridge Proxy TLS Certificate Verification Bypass (CVE-2026-55436)
slug: 2026-07-coder-ai-bridge-proxy-tls-bypass
description: The AI Bridge Proxy (`aibridgeproxyd`) in Coder's platform, when running in its default configuration without an upstream proxy, failed to perform TLS certificate verification for outbound HTTPS connections to the Coder server (CVE-2026-55436), allowing an on-path attacker to intercept sensitive data including Coder session tokens, user-supplied API keys, and full request/response bodies.
date: "2026-07-06T21:16:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - man-in-the-middle
  - tls
  - data-exfiltration
vendors:
  - Coder
products:
  - 'AI Bridge Proxy (vulnerable: >= 2.34.0, < 2.34.2)'
  - 'AI Bridge Proxy (vulnerable: >= 2.33.0, < 2.33.8)'
  - 'AI Bridge Proxy (vulnerable: >= 2.30.0, < 2.32.7)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Supply Chain Compromise
    evidence: An attacker positioned between the proxy and the Coder server, via ARP spoofing, DNS poisoning or control of proxy environment variables, could intercept injected Coder session tokens...
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: An attacker positioned between the proxy and the Coder server... could intercept injected Coder session tokens, user-supplied provider API keys (BYOK) and full request and response bodies including prompts and completions.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Credential Acquisition
    evidence: An attacker positioned between the proxy and the Coder server... could intercept injected Coder session tokens, user-supplied provider API keys (BYOK)...
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-84rm-42xw-mx52
  - CVE-2026-55436
---

A critical vulnerability, CVE-2026-55436, has been identified in the Coder AI Bridge Proxy (`aibridgeproxyd`), affecting versions 2.30.0 through 2.34.1. The proxy, when operating in its default configuration without an explicit upstream proxy, was found to set `InsecureSkipVerify: true` for outbound HTTPS connections to the Coder access URL. This misconfiguration allows the proxy to accept any TLS certificate, bypassing essential verification. An attacker with a Man-in-the-Middle (MITM) position between the AI Bridge Proxy and the Coder server could exploit this to intercept sensitive communications. This vulnerability poses a significant risk to the confidentiality of Coder session tokens, user-supplied provider API keys, and all data exchanged, including prompts and completions.

## Attack Chain

1.  **Initial Access / Positioning**: An attacker gains a Man-in-the-Middle (MITM) position on the network path between the AI Bridge Proxy and the Coder server. This can be achieved through methods like ARP spoofing, DNS poisoning, or by gaining control over environment variables (e.g., `HTTP_PROXY`, `HTTPS_PROXY`) that redirect proxy traffic.
2.  **Outbound Connection**: The `aibridgeproxyd` service initiates an outbound HTTPS connection to the Coder server's access URL to fetch or send data.
3.  **TLS Interception**: The attacker intercepts this HTTPS connection and presents a forged TLS certificate to the AI Bridge Proxy.
4.  **Certificate Acceptance**: Due to the `InsecureSkipVerify: true` setting in the default configuration, the AI Bridge Proxy fails to validate the attacker's forged TLS certificate and establishes a seemingly secure connection with the attacker.
5.  **Traffic Decryption**: The attacker, now acting as an intermediary, can decrypt the traffic flowing between the proxy and the Coder server.
6.  **Sensitive Data Interception**: The attacker extracts sensitive information from the intercepted traffic, including Coder session tokens, user-supplied provider API keys (BYOK), and the full request and response bodies, which may contain AI prompts and completions.
7.  **Impact Fulfillment**: The attacker can use the stolen session tokens or API keys to impersonate users, access data, or perform unauthorized actions within the Coder environment or linked services.

## Impact

The successful exploitation of CVE-2026-55436 allows an attacker to intercept highly sensitive data in transit between the AI Bridge Proxy and the Coder server. This includes Coder session tokens, which could be used for session hijacking and unauthorized access, as well as user-supplied provider API keys (Bring Your Own Key - BYOK) for AI services, leading to compromise of those external accounts. Furthermore, the attacker can access entire request and response bodies, exposing confidential prompts and AI-generated completions. Organizations utilizing Coder deployments where the AI Bridge Proxy communicates with the Coder server over a network path vulnerable to MITM attacks are at risk of significant data breaches and potential credential compromise.

## Recommendation

*   Immediately patch all affected Coder AI Bridge Proxy installations to the latest patched versions: `v2.34.2`, `v2.33.8`, or `v2.32.7` to address CVE-2026-55436.
*   Ensure the Coder access URL uses a trusted certificate to prevent easy spoofing in case of an existing MITM.
*   Secure the network path between the AI Bridge Proxy and the Coder server, for example, by ensuring they are co-located over loopback or by implementing mutual TLS (mTLS) for enhanced authentication.
*   Audit network configurations to identify and mitigate potential Man-in-the-Middle attack vectors, such as insecure DNS configurations or ARP spoofing vulnerabilities.
