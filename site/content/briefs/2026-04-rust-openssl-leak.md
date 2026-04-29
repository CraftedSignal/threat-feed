---
title: rust-openssl Memory Leak via Unchecked Callback Length (CVE-2026-41898)
slug: 2026-04-rust-openssl-leak
description: CVE-2026-41898 describes a vulnerability in rust-openssl where unchecked callback-returned length in PSK and cookie generation can cause OpenSSL to leak adjacent memory to a network peer.
date: "2026-04-29T07:33:41Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - rust-openssl
  - memory-leak
  - tls
  - cve
vendors:
  - Microsoft
cves:
  - id: CVE-2026-41898
    cvss: 9.8
    epss: 0.00042
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41898
rules:
  - title: Detect TLS Handshake with Anomalous Response Size
    description: Detects TLS handshakes where the server response size is significantly larger than expected, potentially indicating a memory leak.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - windows
  - title: Detect process making outbound TLS connections after memory access violation
    description: Detects processes making outbound TLS connections shortly after experiencing a memory access violation, which could indicate exploitation of a memory leak vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-41898 is a security vulnerability affecting the rust-openssl library. The vulnerability stems from a failure to properly validate the length of data returned by callbacks during Pre-Shared Key (PSK) and cookie generation processes within OpenSSL. This oversight can lead to OpenSSL inadvertently exposing adjacent memory regions to a remote network peer. While the exact scope of impact is not detailed in the initial advisory, the potential for memory leakage raises concerns about sensitive information disclosure. Defenders should closely monitor applications utilizing rust-openssl for anomalous behavior indicative of exploitation attempts. The Microsoft Security Response Center published information regarding this vulnerability.

## Attack Chain

1.  A client initiates a TLS handshake with a server using rust-openssl.
2.  The server requests PSK or initiates a cookie exchange as part of the TLS handshake.
3.  rust-openssl triggers a callback function to generate the PSK or cookie data.
4.  The callback function returns data with a length that is not properly validated by rust-openssl.
5.  Due to the unchecked length, OpenSSL reads beyond the intended buffer boundary.
6.  OpenSSL copies the over-read memory region into the response sent to the client.
7.  The client receives the response containing the leaked memory.
8.  The client can then analyze the leaked memory for sensitive information.

## Impact

Successful exploitation of CVE-2026-41898 can lead to the leakage of sensitive information from the server's memory. This information could include cryptographic keys, session data, or other confidential data. The extent of the leak depends on the amount of memory that is read beyond the intended buffer. The vulnerability could affect any application or service that uses rust-openssl for TLS communication and relies on PSK or cookie generation. The number of potential victims is currently unknown, but it would depend on the adoption rate of rust-openssl in security-sensitive applications.

## Recommendation

*   Monitor network traffic for unusually large TLS handshake responses, which may indicate an attempt to trigger the memory leak.
*   Implement robust input validation for callback functions used in PSK and cookie generation within rust-openssl.
*   Deploy the Sigma rules provided to detect potential exploitation attempts based on anomalous network connection patterns.
