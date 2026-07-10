---
title: Tesla HTTP Client Library Vulnerable to Atom Exhaustion Leading to Denial of Service (CVE-2026-48597)
slug: 2026-07-tesla-atom-exhaustion
description: A high-severity denial-of-service vulnerability (CVE-2026-48597) in the `Tesla.Adapter.Mint` component of the Elixir Tesla HTTP client library, affecting versions 1.3.0 through 1.18.2, allows an unauthenticated attacker to crash the underlying BEAM VM by supplying untrusted URL schemes, leading to atom exhaustion.
date: "2026-07-10T00:07:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - elixir
  - erlang
  - vulnerability
  - web-application
vendors:
  - elixir-tesla
products:
  - tesla (>= 1.3.0, < 1.18.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: an attacker who can vary the URL scheme across requests can mint one fresh atom per request and eventually exhaust the table, crashing the VM.
    confidence_band: high
cves:
  - id: CVE-2026-48597
    epss: 0.00301
references:
  - https://github.com/advisories/GHSA-h74c-q9j7-mpcm
  - https://github.com/elixir-tesla/tesla/commit/ccd0823d4ba37581a37d8f6108f9a81b263237ef
  - https://github.com/elixir-tesla/tesla/commit/4699c3cb3e2fd6078f99f45f11cf7466aeedbf0e
---

An unauthenticated attacker can trigger a remote denial-of-service (DoS) condition in applications utilizing the `erlang/tesla` HTTP client library, specifically when configured with `Tesla.Adapter.Mint`. This vulnerability, identified as CVE-2026-48597, affects Tesla versions from 1.3.0 up to 1.18.2. The flaw stems from `Tesla.Adapter.Mint.open_conn/2` passing untrusted URL schemes directly to `String.to_atom/1` without validation. As BEAM (Erlang Virtual Machine) atoms are permanent and its atom table has a finite capacity of approximately 1,048,576 entries, repeatedly supplying unique, non-standard URL schemes (e.g., `atk1://`, `atk2://`) causes the VM to continuously mint new atoms. This eventually exhausts the atom table, leading to an immediate crash of the Elixir/Erlang VM and consequently, the affected application. This attack requires no special privileges beyond the ability to send HTTP requests to a vulnerable application endpoint that processes user-supplied URLs or leverages `Tesla.Middleware.FollowRedirects`.

## Attack Chain

1. An attacker identifies an application using `erlang/tesla` versions 1.3.0 through 1.18.2 with `Tesla.Adapter.Mint` configured, and which exposes an endpoint that processes user-supplied URLs (e.g., a webhook relay, link preview service, or SSRF-style proxy) or includes `Tesla.Middleware.FollowRedirects` in its pipeline.
2. The attacker sends an HTTP request to the vulnerable application, including a URL with a novel, non-standard scheme (e.g., `atk1://attacker.com/path`) in a parameter that the application forwards to the Tesla HTTP client.
3. The `Tesla.Adapter.Mint.open_conn/2` function receives this untrusted URL and extracts the scheme (e.g., "atk1").
4. The extracted scheme is passed directly to `String.to_atom/1`, which creates and interns a new, permanent atom in the BEAM VM's atom table.
5. Although the `Mint` library subsequently rejects the connection attempt due to the unrecognized scheme, the newly created atom persists in the VM's global atom table.
6. The attacker repeats steps 2-5, sending approximately 1,000,000 requests, each with a distinct and previously unused URL scheme (e.g., `atk2://`, `atk3://`, etc.).
7. Upon reaching the BEAM VM's atom table capacity limit (roughly 1,048,576 entries), the `String.to_atom/1` call fails, leading to a fatal error that crashes the entire Elixir/Erlang VM.
8. The application hosting the Tesla client becomes unavailable, resulting in a remote denial-of-service condition.

## Impact

This high-severity vulnerability (CVSS v4.0: 8.2) allows an unauthenticated attacker to remotely trigger a complete denial of service for any application using `erlang/tesla` versions 1.3.0 through 1.18.2 with the `Tesla.Adapter.Mint` adapter. The attack results in a crash of the underlying BEAM Virtual Machine, making the affected application entirely unavailable. No specific victim count or targeted sectors have been publicly identified, but any Elixir application fitting the criteria that processes untrusted URL input is at risk.

## Recommendation

* Patch `erlang/tesla` to version 1.18.3 or later immediately to remediate CVE-2026-48597.
* Review any application features that forward untrusted URLs through `Tesla.Adapter.Mint` and implement robust input validation or allow-listing for URL schemes before passing them to the Tesla client.
* If `Tesla.Middleware.FollowRedirects` is used in conjunction with untrusted inputs, ensure that redirect targets are properly validated and schemes are restricted to `http(s)` to prevent exploitation via malicious `Location` headers.
