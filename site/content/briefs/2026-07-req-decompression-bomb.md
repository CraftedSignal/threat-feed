---
title: Req Library Unbounded Archive/Compression Extraction Denial-of-Service
slug: 2026-07-req-decompression-bomb
description: The Elixir library 'Req' (versions >= 0.1.0, < 0.6.1) is susceptible to a denial-of-service vulnerability (CVE-2026-49755) caused by unbounded archive and compression extraction, which an attacker can leverage by providing a malicious HTTP response with a crafted 'content-type' or 'content-encoding' header, leading to memory exhaustion and application crashes.
date: "2026-07-29T15:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - elixir
  - vulnerability
  - memory-exhaustion
vendors:
  - Erlang
products:
  - Req (>= 0.1.0, < 0.6.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Memory-exhaustion denial of service against any Elixir application that uses Req with its default step pipeline to fetch URLs influenced by an untrusted party, including webhook senders, link previews, OAuth/OIDC discovery clients, package mirrors, image proxies, and any Req.get!/1 call that may follow redirects to attacker-controlled hosts.
    confidence_band: high
cves:
  - id: CVE-2026-49755
    epss: 0.00438
references:
  - https://github.com/advisories/GHSA-655f-mp8p-96gv
---

An attacker can exploit a high-severity denial-of-service vulnerability (CVE-2026-49755) in the Elixir 'Req' library, specifically versions 0.1.0 through 0.6.0. This vulnerability, dubbed a "decompression bomb," arises from Req's default pipeline, which automatically decodes archive and compressed HTTP response bodies without enforcing size limits. By controlling an HTTP endpoint or redirecting a victim's Req client, an attacker can return a small, specially crafted archive or compressed payload. Req's internal processing will then expand this payload into many gigabytes of memory within the Erlang BEAM virtual machine, leading to memory exhaustion and a denial-of-service crash of the Elixir application. This affects applications that fetch untrusted URLs using `Req.get!/1`, such as webhook senders, link previews, OAuth/OIDC discovery clients, and package mirrors.

## Attack Chain

1. An attacker establishes control over an HTTP server or can redirect a victim's Req client to a malicious HTTP endpoint.
2. The attacker configures the malicious server to respond to incoming HTTP requests with an HTTP 200 status code.
3. The response includes a `Content-Type` header specifying an archive format (e.g., `application/zip`) or a `Content-Encoding` header for compression.
4. The attacker crafts a small HTTP response body containing a "decompression bomb" - a highly compressed archive with a single, very large entry (e.g., hundreds of megabytes of zero bytes).
5. A victim Elixir application, using `Req.get!/1` with its default pipeline, sends an HTTP GET request to the attacker-controlled URL.
6. Req's `Req.Steps.decode_body/1` or `Req.Steps.decompress_body/1` steps are invoked automatically based on the `Content-Type` or `Content-Encoding` headers.
7. Req utilizes Erlang's `:zip.extract/2` or `:erl_tar.extract/2` with the `:memory` option, or chains multiple `:zlib` decoders, without applying any size limits.
8. The small compressed payload is fully decompressed or expanded into a large in-memory structure, leading to memory exhaustion of the Erlang BEAM VM and a denial-of-service crash for the victim application.

## Impact

This vulnerability results in a memory-exhaustion denial of service against any Elixir application that uses the Req library with its default step pipeline to fetch URLs influenced by an untrusted party. This includes applications functioning as webhook senders, link preview generators, OAuth/OIDC discovery clients, package mirrors, or image proxies. No authentication is required for exploitation; a single malicious HTTP response can crash the Erlang BEAM virtual machine, potentially taking down unrelated workloads sharing the same VM.

## Recommendation

* Patch affected Req versions by upgrading to Req 0.6.1 or later to mitigate CVE-2026-49755.
* Implement explicit size limits or disable automatic archive/compression decoding when using `Req.get!` to fetch content from untrusted sources, particularly for functionalities like webhook processing or link previews.
* Monitor Elixir application logs for out-of-memory errors or sudden increases in memory usage that could indicate an attempted denial-of-service attack.
