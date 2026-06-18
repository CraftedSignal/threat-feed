---
title: Heimdall Proxy Forwarded Header Injection via Unsanitized Host Header
slug: 2026-06-heimdall-forwarded-header-injection
description: Attackers can exploit Heimdall proxy versions <= 0.17.16 operating in proxy mode by injecting malicious values into the `Host` HTTP header, leading to the construction of a manipulated `Forwarded` header that can spoof client IP addresses for upstream services, potentially bypassing IP-based access controls.
date: "2026-06-18T15:11:26Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - header-injection
  - proxy
  - access-control-bypass
  - ip-spoofing
  - vulnerability
  - web
vendors:
  - dadrus
products:
  - Heimdall (<= 0.17.16)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/advisories/GHSA-4jgr-pg2m-m988
rules:
  - title: Detect Heimdall Host Header Injection Attempt
    description: Detects attempts to exploit Heimdall's vulnerability (GHSA-4jgr-pg2m-m988) by injecting spoofed IP addresses or protocols into the Host header using commas or semicolons, which then gets reflected into the Forwarded header sent to upstream services.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
rules_count: 1
---

A vulnerability (GHSA-4jgr-pg2m-m988) has been identified in Heimdall, an API gateway and access control solution, specifically affecting versions 0.17.16 and earlier when running in proxy mode. This flaw allows attackers to perform `Forwarded` header injection by sending a specially crafted HTTP request where the `Host` header contains unsanitized commas or semicolons followed by `for=` or `proto=`. Heimdall's `proxy/request_context.go` (line 201) directly concatenates the incoming `Host` header value into the `Forwarded` header without proper sanitization, enabling an attacker to inject arbitrary `for=` or `proto=` parameters. This misconfiguration can lead to IP address spoofing, tricking upstream services into believing requests originate from trusted or internal IP addresses (e.g., `127.0.0.1`), thereby facilitating access control bypasses for applications configured behind the Heimdall proxy.

## Attack Chain

1.  An attacker crafts an HTTP GET or POST request targeting a resource behind the vulnerable Heimdall proxy.
2.  The attacker includes a malicious `Host` header in the request, such as `Host: evil.com,for=127.0.0.1` or `Host: legit.com;for=10.0.0.1;proto=https`.
3.  The crafted request is sent to the internet-facing Heimdall proxy instance.
4.  Heimdall receives the request and, operating in proxy mode, prepares to forward it to the configured upstream service.
5.  During request forwarding, Heimdall's Go application code concatenates the raw value of the incoming `Host` header into the new `Forwarded` header without sanitizing commas or semicolons.
6.  Heimdall sends the modified request, now containing an injected `Forwarded` header like `Forwarded: for=1.2.3.4;host=evil.com, for=127.0.0.1;proto=http`, to the upstream application.
7.  The upstream application, configured to trust the `Forwarded` header (especially the last `for=` entry), parses the injected values.
8.  The upstream service misinterprets the spoofed `for=` value as the legitimate client IP, potentially bypassing IP-based access controls (e.g., allowing access to an `/admin-panel`) or logging an incorrect source IP.

## Impact

The primary impact of this vulnerability is the ability for attackers to spoof client IP addresses as seen by upstream services. This can directly lead to unauthorized access to sensitive resources, such as administrator panels or internal APIs, if these services rely on IP-based access controls and trust the `Forwarded` header provided by Heimdall. Organizations using Heimdall in proxy mode with upstream applications that parse and trust the `Forwarded` header, especially those that implement IP allowlisting, are at risk. The vulnerability affects all deployments of Heimdall where these conditions are met, potentially leading to data exfiltration, privilege escalation, or full system compromise of the backend services.

## Recommendation

*   Immediately patch Heimdall installations to a version greater than 0.17.16 to address GHSA-4jgr-pg2m-m988.
*   Deploy the Sigma rules in this brief to your SIEM/detection platform to identify active exploitation attempts against your Heimdall proxy.
*   Review webserver logs for the `cs-host` field to detect patterns indicative of attempted exploitation, as identified in the "Detect Heimdall Host Header Injection Attempt" Sigma rule.
