---
title: Envoy Gateway Authentication Bypass via Path Traversal Leads to Secret Disclosure
slug: 2026-07-envoy-gateway-auth-bypass-secret-disclosure
description: A critical path traversal vulnerability (CVE-2026-53713) exists in the `to_absolute_normalized_path` function of Envoy Gateway due to improper input validation, allowing specially crafted Lua code submitted via an `EnvoyExtensionPolicy` to bypass critical-path checks and read arbitrary sensitive files from the gateway controller pod's filesystem, potentially leading to authentication bypass to the Kubernetes API Server or Gateway XDS server.
date: "2026-07-16T19:24:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - envoy
  - gateway
  - vulnerability
  - path-traversal
  - file-disclosure
  - kubernetes
  - cloud
vendors:
  - Envoy Proxy
products:
  - Envoy Gateway (< 1.7.4)
  - Envoy Gateway (>= 1.8.0-rc.0, < 1.8.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'This allows Lua code submitted as an EnvoyExtensionPolicy to read arbitrary files from the gateway controller pod''s filesystem during Strict validation (the default), including: /etc/passwd Kubernetes SA tokens via //var/run/secrets/kubernetes.io/serviceaccount/token TLS certificates via //certs/... Process environment via //proc/self/environ'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'This allows Lua code submitted as an EnvoyExtensionPolicy to read arbitrary files from the gateway controller pod''s filesystem during Strict validation (the default), including: Kubernetes SA tokens via //var/run/secrets/kubernetes.io/serviceaccount/token TLS certificates via //certs/... Process environment via //proc/self/environ These credentials can be used to read sensitive information from the K8s API Server or from the Gateway XDS server.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wcrf-9vrr-854f
---

A critical vulnerability, tracked as CVE-2026-53713, has been identified in Envoy Gateway versions prior to v1.7.4 and between v1.8.0-rc.0 and v1.8.1. The flaw resides in the `to_absolute_normalized_path` Lua function within the `EnvoyExtensionPolicy` component. This function's failure to properly collapse redundant path separators (e.g., `//` instead of `/`) allows malicious Lua code to craft paths that bypass the `is_critical_path` security check. This bypass enables an attacker to read arbitrary files from the gateway controller pod's filesystem. Successful exploitation can lead to the disclosure of highly sensitive information, including Kubernetes Service Account tokens, TLS certificates, `/etc/passwd`, and process environment variables, potentially granting unauthorized access to the Kubernetes API Server or the Gateway XDS server. This vulnerability presents a severe risk to the confidentiality and integrity of Kubernetes environments utilizing affected Envoy Gateway versions.

## Attack Chain

1. An attacker crafts malicious Lua code designed to read sensitive files.
2. The attacker submits this malicious Lua code as an `EnvoyExtensionPolicy` to the vulnerable Envoy Gateway.
3. The submitted Lua code attempts to access a sensitive file using a path containing redundant separators, such as `//etc/passwd` or `//var/run/secrets/kubernetes.io/serviceaccount/token`.
4. The `to_absolute_normalized_path` function (security.lua:28-43) in Envoy Gateway fails to correctly normalize the path by not collapsing the redundant path separators.
5. Consequently, the `is_critical_path` function, which is designed to prevent access to sensitive locations by checking for paths starting with specific critical prefixes (e.g., `/etc/`), fails to recognize the crafted path (e.g., `//etc/passwd`) as critical because it does not match its expected format.
6. The critical-path check is bypassed due to this input validation flaw.
7. The Envoy Gateway controller pod's filesystem is accessed by the malicious Lua code at the unnormalized path.
8. Arbitrary sensitive files, such as `/etc/passwd`, Kubernetes Service Account tokens, TLS certificates, or process environment variables (`/proc/self/environ`), are read and disclosed to the attacker.
9. The disclosed credentials or sensitive information can then be used to achieve authentication bypass to the Kubernetes API Server or the Gateway XDS server, leading to further compromise.

## Impact

Successful exploitation of CVE-2026-53713 can lead to severe data breaches and system compromise. Attackers can read critical files from the Envoy Gateway controller pod's filesystem, including system user information from `/etc/passwd`, Kubernetes Service Account tokens that provide programmatic access to the Kubernetes API, private TLS certificates, and sensitive environment variables from `/proc/self/environ`. The disclosure of these credentials and sensitive data enables attackers to bypass authentication mechanisms for the Kubernetes API Server or the Gateway XDS server, granting them unauthorized access to manage Kubernetes resources, exfiltrate data, or execute further attacks within the cluster. This could result in complete cluster compromise, affecting all hosted applications and data.

## Recommendation

* Patch CVE-2026-53713 by upgrading Envoy Gateway to version `v1.7.4` or later, or `v1.8.1` or later, on all affected deployments immediately.
* Refer to the "Warning" section in the official Envoy Gateway Lua documentation (as referenced in the source under "Workarounds") for additional measures to reduce risk related to Lua extensibility.
