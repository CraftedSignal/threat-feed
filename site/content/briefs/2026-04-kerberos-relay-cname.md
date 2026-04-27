---
title: Kerberos Authentication Relay via DNS CNAME Abuse (CVE-2026-20929)
slug: 2026-04-kerberos-relay-cname
description: An attacker exploits CVE-2026-20929 by manipulating DNS responses to redirect Kerberos authentication to attacker-controlled AD CS, enabling certificate enrollment for persistent access.
date: "2026-03-31T17:49:30Z"
severities:
  - critical
tags:
  - kerberos
  - relay
  - adcs
  - cve-2026-20929
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
cves:
  - id: CVE-2026-20929
    cvss: 7.5
    epss: 0.00045
references:
  - https://www.crowdstrike.com/en-us/blog/detecting-kerberos-relay-attack-via-dns-cname-abuse/
rules:
  - title: Detect Kerberos Ticket Request for Unusual SPN via DNS CNAME
    description: Detects Kerberos ticket requests where the SPN resolves to an IP address different from the domain.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - dns_query
      - windows
  - title: Detect Access to AD CS Web Enrollment Endpoint
    description: Detects HTTP requests to the AD CS web enrollment endpoint (/certsrv).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-20929, a vulnerability patched in January 2026, allows attackers to perform Kerberos authentication relay attacks by abusing DNS CNAME records. The attack involves manipulating DNS resolution to redirect a client's Kerberos authentication request to an attacker-controlled server. This server then relays the authentication to Active Directory Certificate Services (AD CS) to enroll certificates on behalf of the victim user. This technique allows the attacker to gain persistent access to…
