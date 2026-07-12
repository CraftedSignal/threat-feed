---
title: CVE-2026-56238 - Capgo Supabase PostgREST Information Disclosure
slug: 2026-07-capgo-supabase-info-disclosure
description: An information disclosure vulnerability (CVE-2026-56238) in Capgo before 12.128.2's Supabase PostgREST global_stats endpoint allows unauthenticated attackers to retrieve sensitive financial and operational metrics using a public API key.
date: "2026-07-12T12:21:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - web-application
  - vulnerability
  - supabase
vendors:
  - Capgo
  - Supabase
products:
  - Capgo < 12.128.2
  - Supabase PostgREST
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Capgo before 12.128.2 contains an information disclosure vulnerability in the Supabase PostgREST global_stats endpoint that allows unauthenticated attackers to read sensitive financial and operational metrics using only the public apikey.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1589
    technique_name: Gather Victim Org Information
    evidence: Remote attackers can query the /rest/v1/global_stats endpoint to expose MRR, total revenue, plan-tier revenue breakdown, customer counts, and operational telemetry.
    confidence_band: high
cves:
  - id: CVE-2026-56238
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56238
rules:
  - title: Detect CVE-2026-56238 Exploitation - Supabase PostgREST Global Stats Endpoint Access
    description: Detects exploitation attempts of CVE-2026-56238 by monitoring HTTP GET requests to the vulnerable /rest/v1/global_stats endpoint in Supabase PostgREST used by Capgo, indicating unauthorized information disclosure attempts.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
      - T1589
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-56238 describes an information disclosure vulnerability affecting Capgo software versions prior to 12.128.2. This flaw resides within the Supabase PostgREST `global_stats` endpoint, which is integral to Capgo's backend operations. The vulnerability enables unauthenticated attackers to query the `/rest/v1/global_stats` endpoint. By simply utilizing a publicly available API key, an attacker can gain unauthorized access to highly sensitive financial and operational metrics. This includes data such as Monthly Recurring Revenue (MRR), total revenue figures, a detailed breakdown of revenue by plan tier, customer counts, and various operational telemetry data. The exposure of such data poses a significant risk for organizations using affected Capgo installations, potentially leading to competitive disadvantages, financial fraud, and strategic exploitation due to the revelation of internal business performance.

## Attack Chain

1. An unauthenticated attacker identifies a Capgo instance running a vulnerable version (prior to 12.128.2) of its Supabase PostgREST backend.
2. The attacker crafts an HTTP GET request targeting the `/rest/v1/global_stats` endpoint on the vulnerable Capgo instance. This request includes a public API key, which is sufficient for triggering the vulnerability.
3. The vulnerable Supabase PostgREST endpoint processes the request without proper authentication checks for sensitive data.
4. The endpoint responds by disclosing internal financial and operational metrics, including MRR, total revenue, plan-tier revenue breakdown, customer counts, and operational telemetry to the attacker.
5. The attacker successfully collects and exfiltrates the sensitive organizational data, achieving their objective of information disclosure.

## Impact

The successful exploitation of CVE-2026-56238 results in the unauthorized disclosure of critical business intelligence. Attackers can obtain sensitive financial data, such as Monthly Recurring Revenue (MRR), total revenue, and detailed revenue breakdowns by plan tier. Operational metrics, including customer counts and various telemetry data, are also exposed. This information can be leveraged for competitive intelligence, targeted phishing campaigns, financial fraud, or to undermine the victim organization's market position. While the NVD entry does not specify a number of victims or specific sectors, any organization utilizing vulnerable Capgo instances is at risk of significant reputational and financial damage should their proprietary data be exfiltrated.

## Recommendation

* Patch CVE-2026-56238 by updating Capgo to version 12.128.2 or later immediately to remediate the vulnerability in Supabase PostgREST.
* Deploy the `Detect CVE-2026-56238 Exploitation - Supabase PostgREST Global Stats Endpoint Access` Sigma rule to your SIEM to detect attempts to access the vulnerable `/rest/v1/global_stats` endpoint.
* Block the access to the `/rest/v1/global_stats` URL provided in the IOC section at the perimeter firewall or API gateway if immediate patching is not possible.
* Ensure web server access logs are enabled and retained to provide telemetry for the Sigma rule provided in this brief.
