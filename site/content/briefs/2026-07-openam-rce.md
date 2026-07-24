---
title: OpenAM Unauthenticated Remote Code Execution Vulnerability via Class.forName
slug: 2026-07-openam-rce
description: An unauthenticated remote code execution vulnerability, tracked as CVE-2026-62379, affects OpenAM up to and including version 16.1.1, allowing attackers to achieve full server compromise by sending a crafted XML element to the `/authservice` endpoint that names and instantiates an arbitrary Java class without validation on default configurations.
date: "2026-07-24T21:12:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openam
  - rce
  - java
  - authentication
  - webserver
vendors:
  - OpenAM
products:
  - OpenAM <= 16.1.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A pre-authentication remote code execution vulnerability affects OpenAM. The remote authentication endpoint (`/authservice`, PLL) accepts an XML element that names an arbitrary Java class, which the server then loads and instantiates without validation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation for Client Execution
    evidence: allows an attacker to run code on the server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wg5r-wc3x-39vc
---

A critical pre-authentication remote code execution (RCE) vulnerability, identified as CVE-2026-62379, exists in OpenAM releases up to and including version 16.1.1. This flaw allows an unauthenticated attacker to execute arbitrary code on the server due to improper validation in the remote authentication endpoint, `/authservice`. The vulnerability stems from the `AuthXMLUtils.createCustomCallback` function, which accepts an XML element naming an arbitrary Java class. The OpenAM server then loads and instantiates this class without proper security checks, leading to unauthenticated code execution. This puts any OpenAM instance with default settings at severe risk of complete server compromise, making it a high-priority concern for defenders.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted HTTP POST request to the `/authservice` endpoint of a vulnerable OpenAM server.
2. The POST request includes an XML payload containing an element that specifies an arbitrary Java class name (e.g., `java.lang.Runtime`).
3. The OpenAM server, upon receiving the request, processes the XML payload.
4. The `AuthXMLUtils.createCustomCallback` method is invoked, attempting to load the attacker-specified Java class using `Class.forName`.
5. The server instantiates the arbitrary class without validating its legitimacy or origin.
6. The malicious code embedded within the attacker-controlled Java class executes on the OpenAM server with the privileges of the application.
7. The attacker gains remote code execution capabilities on the server, allowing for full system compromise.

## Impact

Successful exploitation of CVE-2026-62379 results in unauthenticated remote code execution (RCE) and full server compromise on any OpenAM instance running default configurations up to version 16.1.1. This allows an attacker to gain complete control over the affected server, leading to data theft, service disruption, and potentially further network penetration. The vulnerability's pre-authentication nature means that an attacker does not need any prior access or credentials to initiate the attack, making it extremely dangerous. The specific number of victims and targeted sectors are not detailed, but all organizations using the affected OpenAM versions are at risk.

## Recommendation

* Upgrade all OpenAM instances to version `16.1.2` immediately to remediate CVE-2026-62379.
* As an interim mitigation, enable `sunRemoteAuthSecurityEnabled` to require a remote-auth security token, which will reject unauthenticated calls to `/authservice`.
* Restrict or block external network access to the `/authservice` endpoint until systems are patched or the mitigation is in place.
* Deploy the webserver detection rule to identify attempts to access the `/authservice` endpoint, though more specific detection may require application-layer logging for XML body content.
