---
brief_id: brief-2026-06-solarwinds-serv-u-dos
event_id: brief-2026-06-solarwinds-serv-u-dos
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:6dca19eb8635d894b3bd8a4ce95e55b53e05630b8409af509c10538ab737a926
    summary: exploited:true; KEV CVE-2026-28318
    changed_fields:
      - affected_products
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: 'CVE-2026-28318: SolarWinds Serv-U Unauthenticated Denial-of-Service'
slug: 2026-06-solarwinds-serv-u-dos
description: 'CVE-2026-28318 is an uncontrolled resource consumption vulnerability in SolarWinds Serv-U that allows unauthenticated attackers to crash the service by sending specially crafted POST requests utilizing the Content-Encoding: deflate header, leading to a denial-of-service condition.'
date: "2026-06-14T08:56:21Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-05T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:solarwinds:serv-u:*:*:*:*:*:*:*:*
  - cpe:2.3:a:solarwinds:serv-u:15.5.4:-:*:*:*:*:*:*
has_poc: true
tags:
  - denial-of-service
  - vulnerability
  - solarwinds
  - web-server
  - cisa-kev
vendors:
  - SolarWinds
products:
  - Serv-U
product_versions:
  - product: Serv-U
    range: < 15.5.4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.002
    subtechnique_name: Service Exhaustion Flood
cves:
  - id: CVE-2026-28318
    cvss: 7.5
    epss: 0.06262
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-28318
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28318
  - https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_15-5-4-hotfix-1_release_notes.htm#link7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28318
  - https://ccb.belgium.be/advisories/warning-actively-exploited-high-criticality-uncontrolled-resource-consumption
rules:
  - title: Detect CVE-2026-28318 Exploitation - Serv-U DoS Attempt
    description: 'Detects CVE-2026-28318 exploitation — HTTP POST requests to a web server with ''Content-Encoding: deflate'' header, indicating an attempt to trigger the Serv-U uncontrolled resource consumption vulnerability.'
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-06-14T09:47:54Z"
    level: L2
    summary: poc_available; serv-u version < 15.5.4
    sources:
      - ccb-belgium
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-28318
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2026-28318 is an uncontrolled resource consumption vulnerability affecting SolarWinds Serv-U, a popular managed file transfer (MFT) solution. This vulnerability allows an unauthenticated attacker to remotely trigger a denial-of-service (DoS) condition by sending specially crafted HTTP POST requests that contain the `Content-Encoding: deflate` header. When the vulnerable Serv-U instance attempts to process these requests, it consumes excessive resources, leading to the service crashing and becoming unavailable. The vulnerability was added to CISA's Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild or a significant risk thereof, and mandates federal agencies to apply mitigations by June 19, 2026. This threat is critical for organizations relying on Serv-U for file transfers, as its unavailability can severely disrupt business operations.

## Attack Chain

1.  **Reconnaissance**: An attacker identifies an internet-exposed SolarWinds Serv-U instance, often using tools like Shodan or other OSINT sources.
2.  **Request Crafting**: The attacker crafts a malicious HTTP POST request designed to exploit the uncontrolled resource consumption vulnerability.
3.  **Header Injection**: The crafted POST request specifically includes the `Content-Encoding: deflate` header, instructing the server to decompress the request body.
4.  **Payload Delivery**: The attacker sends the specially crafted POST request, which may contain malformed or excessively large deflate-encoded data, to the vulnerable Serv-U web server.
5.  **Resource Consumption**: The Serv-U service attempts to decompress and process the `deflate`-encoded content in the request, triggering uncontrolled resource consumption (e.g., CPU, memory).
6.  **Service Crash**: Due to the vulnerability, the Serv-U process becomes unstable and eventually crashes, terminating the application.
7.  **Denial of Service**: The SolarWinds Serv-U service becomes unavailable, preventing legitimate users from accessing or transferring files and disrupting critical business functions.

## Impact

Successful exploitation of CVE-2026-28318 results in a complete denial-of-service for the affected SolarWinds Serv-U instance. Since Serv-U is often used for critical file transfer operations, its unavailability can lead to severe operational disruptions, data access issues, and potential financial losses for affected organizations. While the vulnerability itself does not allow for data exfiltration or remote code execution, a DoS attack can severely impact business continuity and may also be used as a distraction for other concurrent attack activities. The CISA KEV catalog listing underscores the severity and observed real-world impact of this vulnerability.

## Recommendation

*   Apply vendor patches for CVE-2026-28318 immediately as outlined by SolarWinds, specifically updating to Serv-U 15.5.4 Hotfix 1 or later.
*   Deploy the provided Sigma rule "Detect CVE-2026-28318 Exploitation - Serv-U DoS Attempt" to your SIEM to identify attempted exploitation.
*   Enable comprehensive web server logging for your Serv-U instances, capturing full HTTP request headers and methods, to aid in detecting and investigating exploitation attempts.
*   Implement CISA BOD 22-01 guidance for all applicable federal agencies and consider discontinuing use if unable to apply mitigations or patches.
