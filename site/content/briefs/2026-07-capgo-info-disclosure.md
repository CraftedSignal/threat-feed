---
title: Capgo Information Disclosure in get_orgs_v7 RPC Function (CVE-2026-56279)
slug: 2026-07-capgo-info-disclosure
description: Capgo versions prior to 12.128.2 are vulnerable to an information disclosure flaw in the `get_orgs_v7(userid)` RPC function, allowing unauthenticated attackers to retrieve sensitive foreign user and organization data by supplying arbitrary user UUIDs.
date: "2026-07-10T15:23:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - rpc
vendors:
  - Capgo
products:
  - Capgo (< 12.128.2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Network Information
    evidence: Unauthenticated attackers can supply arbitrary user UUIDs to retrieve foreign users' organization membership, roles, management emails, and billing metadata.
    confidence_band: high
cves:
  - id: CVE-2026-56279
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56279
  - https://github.com/Cap-go/capgo/security/advisories/GHSA-fch8-pp28-mw2x
  - https://www.vulncheck.com/advisories/capgo-information-disclosure-via-get-orgs-v7-rpc-endpoint
rules:
  - title: Detect CVE-2026-56279 Exploitation - Capgo get_orgs_v7 RPC Information Disclosure
    description: Detects attempts to exploit CVE-2026-56279, an information disclosure vulnerability in Capgo's get_orgs_v7 RPC function, by monitoring for requests to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-56279 describes an information disclosure vulnerability affecting Capgo versions prior to 12.128.2. The vulnerability resides within the `get_orgs_v7(userid)` Remote Procedure Call (RPC) function, which, despite being intended for private access with specific access controls, remains publicly invokable. This flaw enables unauthenticated attackers to interact with the function and supply arbitrary user Universally Unique Identifiers (UUIDs) as parameters. Upon successful exploitation, the function inadvertently returns sensitive data, including foreign users' organization membership details, roles, management email addresses, and billing metadata. This exposure of sensitive organizational and user information could facilitate further targeted attacks, social engineering campaigns, or identity theft.

## Attack Chain

1. **Vulnerability Discovery**: An unauthenticated attacker identifies a Capgo instance that is vulnerable to CVE-2026-56279 (Capgo version before 12.128.2).
2. **RPC Function Access**: The attacker sends a crafted HTTP request directly targeting the `get_orgs_v7(userid)` RPC endpoint.
3. **Arbitrary User ID Provision**: The attacker includes arbitrary user UUIDs as parameters within the crafted request to query for specific user or organization data.
4. **Authorization Bypass**: Due to the "Missing Authorization" vulnerability (CWE-862) in the `get_orgs_v7(userid)` function, the access controls intended to protect the function are bypassed.
5. **Information Retrieval**: The vulnerable Capgo instance processes the unauthorized request and returns sensitive data associated with the supplied user UUIDs.
6. **Data Collection**: The attacker successfully collects disclosed information, including foreign users' organization membership, roles, management emails, and billing metadata.
7. **Subsequent Exploitation**: The gathered sensitive data can be leveraged for further malicious activities, such as targeted phishing campaigns, social engineering, or identity theft against the affected users and organizations.

## Impact

The successful exploitation of CVE-2026-56279 leads to significant information disclosure. Attackers can obtain sensitive organizational data, including the internal structure, roles, management contacts, and financial details (billing metadata) of foreign users. This sensitive information can be highly valuable for subsequent targeted attacks, facilitating sophisticated social engineering, business email compromise (BEC) schemes, or credential harvesting operations. While no specific victim count or sectors are mentioned, any organization using affected Capgo versions is at risk of having their user and organizational data compromised.

## Recommendation

* Patch Capgo instances immediately to version 12.128.2 or later to address CVE-2026-56279.
* Deploy the Sigma rule "Detect CVE-2026-56279 Exploitation - Capgo get_orgs_v7 RPC Information Disclosure" to your SIEM to monitor for suspicious access attempts to the `get_orgs_v7` RPC endpoint.
* Review web server logs for requests to URIs containing `/get_orgs_v7` to identify any past exploitation attempts.
