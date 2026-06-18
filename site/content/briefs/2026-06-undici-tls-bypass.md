---
title: undici TLS Validation Bypass via SOCKS5 ProxyAgent (CVE-2026-9697)
slug: 2026-06-undici-tls-bypass
description: A vulnerability in undici's ProxyAgent, when configured with a SOCKS5 proxy, causes the `requestTls` option to be silently dropped. This bypasses user-configured TLS certificate validation settings (e.g., custom CAs), allowing HTTPS connections through the SOCKS5 tunnel to fall back to the Node.js default trust store. This flaw enables Man-in-the-Middle (MITM) attacks, where any publicly-trusted certificate for the target hostname would be accepted, compromising the intended certificate pinning and allowing attackers to read or tamper with HTTPS traffic.
date: "2026-06-18T14:51:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - tls-bypass
  - node.js
  - npm
vendors:
  - undici
products:
  - undici (>= 7.23.0, < 7.28.0)
  - undici (>= 8.0.0, < 8.5.0)
references:
  - https://github.com/advisories/GHSA-vmh5-mc38-953g
rules:
  - title: Detect Vulnerable undici Package Versions (CVE-2026-9697)
    description: Detects the presence of `package.json` files specifying vulnerable versions of the `undici` library, which are affected by CVE-2026-9697 (TLS validation bypass). This rule helps identify applications that need to be upgraded.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    data_sources:
      - file_event
      - linux
  - title: Detect Node.js Process Initiating SOCKS5 Proxy Connection
    description: Detects Node.js processes launched with command-line arguments indicative of using a SOCKS5 proxy. This can highlight applications that utilize `undici`'s `ProxyAgent` with SOCKS5, potentially making them vulnerable to CVE-2026-9697 if `undici` is not patched.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `undici` HTTP/1.1 client for Node.js, specifically its `ProxyAgent` component, is affected by CVE-2026-9697, a critical TLS certificate validation bypass vulnerability. This flaw, introduced in `undici` versions 7.23.0 and 8.0.0, occurs when the `ProxyAgent` is configured to use a SOCKS5 proxy. In such scenarios, the `requestTls` option, intended for strict TLS validation (e.g., pinning to internal CAs or custom certificates), is silently ignored. As a result, HTTPS connections established through the SOCKS5 tunnel default to Node.js's standard trust store. This allows an attacker, capable of performing a Man-in-the-Middle (MITM) attack, to present any valid certificate signed by a publicly trusted Certificate Authority, thereby bypassing the application's intended certificate pinning and enabling the interception and potential manipulation of encrypted traffic. Defenders should prioritize patching and reassess network configurations involving `undici` and SOCKS5 proxies.

## Attack Chain

1.  **Initial Access (Attacker Pre-condition):** An attacker establishes a Man-in-the-Middle (MITM) position, enabling them to intercept network traffic between a vulnerable Node.js application and its target HTTPS server (e.g., via DNS poisoning, rogue Wi-Fi, compromised network infrastructure, or controlling the SOCKS5 proxy itself).
2.  **Vulnerable Application Execution:** A Node.js application, utilizing `undici`'s `ProxyAgent` (or `Socks5ProxyAgent` directly) with a SOCKS5 proxy URI (e.g., `socks5://proxy.attacker.com`), attempts to establish an HTTPS connection to a target server, while being configured to enforce strict TLS validation via the `requestTls` option (e.g., pinning to a custom Certificate Authority).
3.  **TLS Option Dropped:** Due to the vulnerability (CVE-2026-9697), `undici`'s `ProxyAgent` silently disregards the `requestTls` configuration (including `ca`, `cert`, `key`, `rejectUnauthorized`, `servername`) that was specified for the outgoing HTTPS connection.
4.  **Fallback to Default Trust Store:** The vulnerable application proceeds to establish the HTTPS connection, but instead of using the application's defined `requestTls` settings, it defaults to Node.js's standard trust store (typically the Mozilla CA bundle) for validating the target server's certificate.
5.  **Attacker Certificate Presentation:** The attacker, from their MITM vantage point, intercepts the TLS handshake and presents a valid HTTPS certificate for the target hostname, which is signed by *any* publicly trusted Certificate Authority.
6.  **Certificate Acceptance and MITM:** The vulnerable application, now relying on the default trust store, accepts the attacker's certificate as legitimate because it is signed by a publicly trusted CA. This bypasses the application's intended strict TLS pinning and validation.
7.  **Data Interception and Tampering:** The attacker can now transparently decrypt, inspect, modify, and re-encrypt the HTTPS traffic flowing between the vulnerable Node.js application and the legitimate target server, allowing for full Man-in-the-Middle capabilities.

## Impact

The impact of CVE-2026-9697 is severe for applications relying on `undici`'s `ProxyAgent` with SOCKS5 proxies for secure HTTPS communication, especially those implementing certificate pinning or custom CA trust. If exploited, an attacker positioned in a Man-in-the-Middle (MITM) role can completely bypass intended TLS security controls. This allows them to intercept sensitive data transmitted over HTTPS, including credentials, personal identifiable information (PII), and proprietary business data. Furthermore, the attacker can tamper with this data, potentially leading to unauthorized transactions, data corruption, or execution of malicious commands within the application's context. While specific victim counts are not available, any organization using affected `undici` versions in conjunction with SOCKS5 proxies for critical application-to-application communication is at risk.

## Recommendation

*   **Upgrade undici immediately:** Upgrade affected Node.js applications to `undici` v7.28.0 or v8.5.0 to remediate CVE-2026-9697.
*   **Deploy package version detection:** Deploy the provided Sigma rule "Detect Vulnerable undici Package Versions (CVE-2026-9697)" to identify affected systems within your environment.
*   **Implement workaround if upgrade isn't possible:** If an immediate upgrade is not feasible, reconfigure `ProxyAgent` to route traffic through an HTTP-proxy instead of SOCKS5 when `requestTls` is required for strict validation, as `requestTls` is honored correctly for HTTP proxies.
*   **Monitor for Node.js SOCKS5 usage:** Deploy the "Detect Node.js Process Initiating SOCKS5 Proxy Connection" Sigma rule to identify Node.js applications potentially using SOCKS5 proxies, which may indicate vulnerable configurations if combined with `undici`.
