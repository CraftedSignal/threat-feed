---
brief_id: brief-2026-05-langflow-cors
event_id: brief-2026-05-langflow-cors
revision: 1
activity_at: "2026-05-21T18:58:51Z"
title: Langflow Origin Validation Error Vulnerability (CVE-2025-34291)
slug: 2026-05-langflow-cors
description: Langflow contains an origin validation error vulnerability (CVE-2025-34291) due to an overly permissive CORS configuration combined with a refresh token cookie configured as SameSite=None, allowing malicious webpages to perform cross-origin requests and potentially leading to arbitrary code execution and full system compromise.
date: "2026-05-21T18:58:51Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-21T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=5AB85FC2-7A7B-5CF1-ABF2-AC44C5026986&utm_source=rss&utm_medium=rss
tags:
  - cve-2025-34291
  - cors
  - csrf
  - langflow
  - cloud
  - origin validation
vendors:
  - Langflow
  - Palo Alto Networks
products:
  - Langflow
  - Langflow < 1.3.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-34291
    cvss: 8.8
    epss: 0.312
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2025-34291
  - https://github.com/langflow-ai/langflow
  - https://github.com/langflow-ai/langflow/releases/tag/v1.9.3
  - https://github.com/langflow-ai/langflow/issues/11465#event-25774545848
  - https://nvd.nist.gov/vuln/detail/CVE-2025-34291
  - https://sploitus.com/exploit?id=5AB85FC2-7A7B-5CF1-ABF2-AC44C5026986&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Langflow CVE-2025-34291 Exploitation Attempt via Malicious Referer
    description: Detects CVE-2025-34291 exploitation attempt by monitoring for HTTP requests to Langflow with a suspicious Referer header indicating a cross-origin request from a potentially malicious domain.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Langflow CVE-2025-34291 Post-Exploitation Activity via Token Usage
    description: Detects CVE-2025-34291 post-exploitation activity by monitoring for API calls to authenticated endpoints after successful refresh token usage from a suspicious IP.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-05-22T21:01:28Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-34291
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Langflow is vulnerable to an origin validation error (CVE-2025-34291) stemming from a misconfiguration of Cross-Origin Resource Sharing (CORS). This, combined with the use of a refresh token cookie lacking proper SameSite restrictions (SameSite=None), allows attackers to bypass standard browser security mechanisms.  A malicious actor can craft a webpage that, when visited by an authenticated Langflow user, can make unauthorized cross-origin requests to the Langflow server. This vulnerability allows an attacker to call the refresh endpoint and obtain tokens to access authenticated endpoints. The attacker can then leverage these tokens to perform actions as the compromised user, potentially leading to complete system compromise and data exfiltration. This vulnerability affects installations of Langflow prior to version 1.9.3.

## Attack Chain

1.  Attacker identifies a Langflow instance with a vulnerable CORS configuration and SameSite=None refresh token cookie.
2.  Attacker crafts a malicious webpage designed to exploit the CORS misconfiguration.
3.  The attacker distributes the malicious webpage via phishing or other social engineering tactics.
4.  Victim, an authenticated Langflow user, visits the malicious webpage.
5.  The malicious webpage executes JavaScript code that initiates a cross-origin request to the Langflow server, including the refresh token cookie.
6.  Due to the permissive CORS policy and missing SameSite attribute, the Langflow server processes the request and returns a valid access token to the malicious webpage.
7.  The attacker uses the obtained access token to access authenticated endpoints on the Langflow server, performing actions as the compromised user.
8.  The attacker leverages the compromised access to execute arbitrary code and gain full system compromise, potentially exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2025-34291 can lead to complete compromise of a Langflow installation. An attacker can gain unauthorized access to sensitive data, execute arbitrary code on the server, and potentially pivot to other systems within the network. The lack of proper origin validation makes Langflow instances highly susceptible to cross-site request forgery (CSRF) attacks, where authenticated users are tricked into performing actions without their knowledge or consent. This could affect any Langflow deployment, including cloud-based and on-premise installations.

## Recommendation

*   Apply the mitigations as documented in the vendor advisory ([https://github.com/langflow-ai/langflow](https://github.com/langflow-ai/langflow)).
*   Upgrade Langflow to version 1.9.3 or later, which addresses the CORS misconfiguration ([https://github.com/langflow-ai/langflow/releases/tag/v1.9.3](https://github.com/langflow-ai/langflow/releases/tag/v1.9.3)).
*   Implement stricter CORS policies to restrict cross-origin requests to only trusted domains.
*   Configure refresh token cookies with the `SameSite=Strict` or `SameSite=Lax` attribute to prevent them from being sent with cross-origin requests.
*   Deploy the Sigma rule `Detect Langflow CVE-2025-34291 Exploitation Attempt via Malicious Referer` to identify potential exploitation attempts based on the Referer header.
*   Apply applicable BOD 22-01 guidance for cloud services as recommended by CISA.
