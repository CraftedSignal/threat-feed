---
title: SolarEdge CSRF and Out-of-Band Injection Vulnerability
slug: 2026-05-solaredge-csrf-oob-injection
description: A CSRF-OOB-Injection vulnerability exists in SolarEdge Monitoring Platform's `/solaredge-web/p/initClient` endpoint due to improper validation of session parameters, allowing attackers to manipulate headers to initiate requests to attacker-controlled domains, potentially leading to session compromise and unauthorized system control.
date: "2026-05-21T13:32:19Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - solaredge
  - csrf
  - oob-injection
  - webapps
vendors:
  - SolarEdge Technologies Ltd.
products:
  - SolarEdge Monitoring Platform - Framework /solaredge-web/
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.exploit-db.com/exploits/52569
iocs:
  - type: domain
    value: cn3iam50ywo00n2a5vvi3o59r0xrln9c.oastify.com
ioc_counts:
  domain: 1
rules:
  - title: Detect SolarEdge Out-of-Band Injection via X-Forwarded-For
    description: Detects attempts to exploit the SolarEdge OOB injection vulnerability by monitoring the X-Forwarded-For header for suspicious domain patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SolarEdge CSRF to Create Cookie
    description: Detects potential CSRF attacks against SolarEdge by monitoring POST requests to /solaredge-web/p/initClient to create a cookie.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A cross-site request forgery (CSRF) and out-of-band (OOB) injection vulnerability has been identified in the SolarEdge Monitoring Platform, specifically affecting the `/solaredge-web/p/initClient` endpoint. The vulnerability, discovered by nu11secur1ty, stems from a business logic flaw that allows the generation and overwriting of session parameters without proper origin validation. An attacker can leverage this vulnerability to force a legitimate operator's browser to execute unauthorized commands. Additionally, by manipulating the `X-Forwarded-For` and `Referer` headers, an attacker can force the SolarEdge internal infrastructure to initiate requests to external, attacker-controlled domains, demonstrating a lack of framework-level filtration. This could lead to session compromise and potential unauthorized control over photovoltaic systems.

## Attack Chain

1.  Attacker crafts a malicious HTML page containing a POST request to `/solaredge-web/p/initClient` with the `cmd=createCookie` parameter.
2.  The crafted POST request sets arbitrary session parameters due to the lack of CSRF protection.
3.  The attacker manipulates the `X-Forwarded-For` header to point to an attacker-controlled domain (e.g., `cn3iam50ywo00n2a5vvi3o59r0xrln9c.oastify.com`).
4.  The attacker may also manipulate the `Referer` header to further control the request's origin.
5.  A victim user visits the attacker-controlled webpage, triggering the CSRF attack.
6.  The victim's browser sends the crafted POST request to the SolarEdge Monitoring Platform.
7.  The SolarEdge infrastructure initiates an out-of-band request to the attacker-controlled domain specified in the `X-Forwarded-For` header.
8.  The attacker gains unauthorized access to the SolarEdge platform through session hijacking or gains information about the internal infrastructure.

## Impact

Successful exploitation of this vulnerability could allow an attacker to hijack legitimate user sessions on the SolarEdge Monitoring Platform. This can lead to unauthorized monitoring, modification, or control of physical photovoltaic systems managed through the platform. An attacker could potentially disrupt energy production, tamper with system settings, or gain access to sensitive data. The lack of specific victim count or sector information limits a precise impact assessment.

## Recommendation

*   Implement CSRF protection measures on the `/solaredge-web/p/initClient` endpoint to prevent unauthorized session parameter manipulation, mitigating the primary CSRF vulnerability described in the Overview.
*   Sanitize and validate the `X-Forwarded-For` and `Referer` headers to prevent out-of-band injection attacks, blocking requests to attacker-controlled domains such as `cn3iam50ywo00n2a5vvi3o59r0xrln9c.oastify.com` (IOC).
*   Deploy the Sigma rule "Detect SolarEdge Out-of-Band Injection via X-Forwarded-For" to identify attempts to exploit this vulnerability in web server logs.
