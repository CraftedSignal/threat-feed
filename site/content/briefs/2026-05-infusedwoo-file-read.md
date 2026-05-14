---
title: InfusedWoo Pro WordPress Plugin Arbitrary File Read Vulnerability (CVE-2026-6514)
slug: 2026-05-infusedwoo-file-read
description: The InfusedWoo Pro plugin for WordPress is vulnerable to arbitrary file read in versions up to 5.1.2, allowing unauthenticated attackers to make web requests to arbitrary locations, potentially querying and modifying information from internal services.
date: "2026-05-14T09:17:13Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - wordpress
  - plugin
  - arbitrary file read
  - ssrf
vendors:
  - Wordfence
products:
  - InfusedWoo Pro
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6514
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6514
  - https://downloads.infusedwoo.com/updater/iw5.php?changelog
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/76b75e61-e7f8-41cc-ab4f-e6ca42d68308?source=cve
rules:
  - title: Detect CVE-2026-6514 Exploitation — InfusedWoo Pro Arbitrary File Read
    description: Detects CVE-2026-6514 exploitation — Attempts to exploit the arbitrary file read vulnerability in the InfusedWoo Pro plugin by sending requests to the popup_submit endpoint with suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-6514 Exploitation — InfusedWoo Pro popup_submit SSRF via Local File
    description: Detects CVE-2026-6514 exploitation — Detects potential SSRF attempts via the popup_submit function with file:// scheme.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The InfusedWoo Pro plugin for WordPress is susceptible to an arbitrary file read vulnerability (CVE-2026-6514) affecting versions up to and including 5.1.2. This flaw allows unauthenticated attackers to perform server-side request forgery (SSRF) attacks by manipulating the `popup_submit` functionality. By crafting malicious web requests, attackers can potentially access sensitive information from internal services or resources accessible to the WordPress server, posing a significant risk to data confidentiality and system integrity. The vulnerability was reported by Wordfence.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable InfusedWoo Pro plugin (version <= 5.1.2).
2. The attacker crafts a malicious HTTP request targeting the `popup_submit` endpoint.
3. The crafted request contains a URL pointing to an internal resource or service.
4. The WordPress server, acting on behalf of the attacker, makes a request to the specified internal URL.
5. The response from the internal resource is returned to the attacker, effectively bypassing access controls.
6. The attacker reads sensitive files or queries internal services, gathering information about the target network.
7. The attacker may potentially leverage the SSRF vulnerability to modify data on internal services.

## Impact

Successful exploitation of this vulnerability (CVE-2026-6514) allows an unauthenticated attacker to read arbitrary files and potentially interact with internal services accessible to the WordPress server. This could lead to the exposure of sensitive data, such as configuration files, database credentials, or API keys. It could also enable further attacks, such as privilege escalation or lateral movement within the internal network. The severity of the impact depends on the type and sensitivity of the data and services exposed through the SSRF vulnerability.

## Recommendation

*   Upgrade the InfusedWoo Pro plugin to a version higher than 5.1.2 to patch CVE-2026-6514.
*   Deploy the Sigma rule "Detect CVE-2026-6514 Exploitation — InfusedWoo Pro Arbitrary File Read" to detect exploitation attempts targeting the vulnerable `popup_submit` endpoint.
*   Review webserver logs for unusual requests to `popup_submit` as described in the Sigma rule, especially those containing suspicious URLs.
