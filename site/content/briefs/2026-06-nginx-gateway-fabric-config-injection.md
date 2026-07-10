---
title: 'CVE-2026-50107: NGINX Gateway Fabric Configuration Injection Vulnerability'
slug: 2026-06-nginx-gateway-fabric-config-injection
description: An injection vulnerability, CVE-2026-50107, exists in the NGINX configuration generator component of NGINX Gateway Fabric when configured with NGINX Plus or NGINX Open Source as the data plane, allowing authenticated attackers with CRD modification permissions to inject arbitrary NGINX configuration directives via unsanitized user-supplied string values in the access log format setting, leading to control plane compromise and potential defense evasion or system impact.
date: "2026-06-17T20:39:52Z"
lastmod: "2026-07-10T11:52:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:nginx_gateway_fabric:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_ingress_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_ingress_controller:4.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_ingress_controller:4.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_instance_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B132E072-36D8-5390-949D-A06FA9ADC7B5&utm_source=rss&utm_medium=rss
tags:
  - config-injection
  - nginx
  - kubernetes
  - cloud-native
  - web-vulnerability
  - cve
vendors:
  - NGINX
  - F5
  - NGINX, Inc.
  - Alibaba
products:
  - NGINX Plus
  - NGINX Open Source
  - NGINX Gateway Fabric
  - nginx < 1.31.2
  - XQUIC (<= v1.9.4)
  - Tengine
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-50107
    cvss: 8.1
    epss: 0.00492
  - id: CVE-2026-42530
    cvss: 8.1
    epss: 0.03225
  - id: CVE-2026-11311
    cvss: 8.1
    epss: 0.00567
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50107
  - https://www.securityweek.com/f5-patches-critical-high-severity-nginx-vulnerabilities/
  - https://sploitus.com/exploit?id=B132E072-36D8-5390-949D-A06FA9ADC7B5&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/07/unpatched-xring-flaw-in-xquic-lets.html
rules:
  - title: Detect NginxProxy CRD Modification with Malicious Access Log Format
    description: Detects CVE-2026-50107 exploitation — attempts to create or update NginxProxy CRDs with NGINX configuration injection keywords in the access log format setting, indicative of arbitrary NGINX directive injection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - audit_logs
      - kubernetes
  - title: Detect NGINX Process Reload Initiated by Anomalous User or Process
    description: Detects an NGINX process reload or restart command executed by a user or process not typically associated with NGINX Gateway Fabric operations, which could indicate post-exploitation activity after configuration injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-06-18T09:43:32Z"
    level: L2
    summary: added CVE-2026-11311 +3
    sources:
      - securityweek
  - at: "2026-06-19T20:08:42Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
  - at: "2026-07-10T11:52:12Z"
    level: L2
    summary: added CVE-2026-11311 +1
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/unpatched-xring-flaw-in-xquic-lets.html
---

A critical injection vulnerability, identified as CVE-2026-50107, affects NGINX Gateway Fabric when utilizing NGINX Plus or NGINX Open Source as its data plane. This flaw resides within the NGINX configuration generator component, where user-supplied string values provided in the `access log format` setting of `NginxProxy` Custom Resource Definitions (CRDs) are directly rendered into NGINX configuration templates without proper sanitization or escaping. An authenticated attacker, possessing the necessary permissions to create or modify these CRDs, can exploit this vulnerability to craft malicious values, effectively injecting arbitrary NGINX configuration directives. This is fundamentally a control plane issue, meaning the direct trigger occurs at the management layer, enabling unauthorized changes to the NGINX data plane's behavior without direct data plane exposure during the exploitation itself.

## Attack Chain

1.  An authenticated attacker gains access to a Kubernetes cluster where NGINX Gateway Fabric is deployed.
2.  The attacker leverages existing permissions or exploits another vulnerability to obtain permissions to create or modify `NginxProxy` Custom Resource Definitions (CRDs) within the cluster.
3.  The attacker crafts a malicious `NginxProxy` CRD (or modifies an existing one) to include specially crafted string values in the `spec.accessLog.format` field.
4.  The malicious `access log format` string contains NGINX configuration directives designed for injection, such as `set $variable`, `proxy_pass`, `add_header`, or `if` statements.
5.  NGINX Gateway Fabric's configuration generator processes the attacker-controlled `NginxProxy` CRD and directly renders the unsanitized `access log format` string into the underlying NGINX configuration templates.
6.  Arbitrary NGINX configuration directives are injected into the dynamically generated NGINX configuration files on the data plane nodes.
7.  The NGINX data plane instances reload their configuration, activating the malicious directives which can lead to defense evasion, traffic manipulation, data exfiltration, or denial of service.

## Impact

The successful exploitation of CVE-2026-50107 allows an attacker to inject arbitrary NGINX configuration directives. This control plane compromise can lead to significant impacts on the affected services. Attackers could manipulate traffic routing, bypassing security controls, redirecting legitimate requests, or enabling internal network access. They could also modify NGINX logging configurations to exfiltrate sensitive data or disrupt service availability by introducing malformed or conflicting directives, leading to application denial of service. Furthermore, injected directives could be used to install persistent backdoors within the NGINX configuration, making detection and remediation more challenging. The CVSSv3.1 Base Score of 8.1 indicates a high severity threat.

## Recommendation

*   Patch CVE-2026-50107 immediately by upgrading NGINX Gateway Fabric and its associated components to the versions specified in the vendor's security advisory.
*   Implement robust Kubernetes Role-Based Access Control (RBAC) to restrict permissions for creating or modifying `NginxProxy` CRDs to only authorized and necessary users/service accounts.
*   Deploy the Sigma rule "Detect NginxProxy CRD Modification with Malicious Access Log Format" to your Kubernetes audit log monitoring solution to identify attempts to exploit this vulnerability.
*   Monitor for unauthorized or anomalous NGINX process reloads or restarts on data plane nodes using the "Detect NGINX Process Reload Initiated by Anomalous User or Process" Sigma rule.
