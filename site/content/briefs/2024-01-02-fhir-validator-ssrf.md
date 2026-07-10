---
title: FHIR Validator SSRF via /loadIG Leads to Credential Theft
slug: 2024-01-02-fhir-validator-ssrf
description: The FHIR Validator HTTP service is vulnerable to server-side request forgery (SSRF) via the `/loadIG` endpoint, enabling attackers to steal authentication tokens by exploiting a prefix-matching flaw in the credential provider.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - fhir
  - credential-theft
  - vulnerability
products:
  - FHIR Validator
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
references:
  - https://github.com/advisories/GHSA-vr79-8m62-wh98
iocs:
  - type: url
    value: https://packages.fhir.org.attacker.com/malicious-ig
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious FHIR Validator /loadIG SSRF Attempt
    description: Detects attempts to exploit the FHIR Validator SSRF vulnerability by monitoring POST requests to the `/loadIG` endpoint with suspicious URLs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect FHIR Validator Credential Leak via Outbound Connection
    description: Detects potential credential leakage by monitoring outbound network connections from the FHIR Validator process to suspicious domains.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1199
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The FHIR Validator HTTP service is susceptible to a server-side request forgery (SSRF) vulnerability through the unauthenticated `/loadIG` endpoint. This endpoint, intended for loading Implementation Guides (IGs), can be abused to make outbound HTTP requests to attacker-controlled URLs. The vulnerability stems from a combination of the SSRF and a flaw in how the application handles authentication credentials. Specifically, the `ManagedWebAccessUtils.getServer()` function uses `startsWith()` for URL prefix matching when determining whether to attach authentication tokens. An attacker can exploit this by registering a domain that is a prefix of a legitimate FHIR server URL, causing the application to send the server's authentication tokens (Bearer, Basic, API keys) to the attacker's domain. This flaw affects FHIR Validator versions prior to 6.9.4. Successful exploitation leads to credential theft, potentially enabling supply chain attacks and data breaches.

## Attack Chain

1.  The attacker sends a POST request to the `/loadIG` endpoint of the FHIR Validator HTTP service.
2.  The POST request contains a JSON body with an `ig` field set to an attacker-controlled URL that is a prefix of a legitimate FHIR server URL (e.g., `https://packages.fhir.org.attacker.com/malicious-ig`).
3.  The FHIR Validator processes the request and uses `IgLoader.loadIg()` to load the IG, triggering `ManagedWebAccess.get()` to fetch content from the specified URL.
4.  `ManagedWebAccess.get()` creates a `SimpleHTTPClient` and attaches an `authProvider`.
5.  The `authProvider` uses `startsWith()` to check if the attacker-controlled URL matches the prefix of any configured FHIR server URLs.
6.  Due to the prefix match, the authentication tokens (Bearer, Basic, API keys) associated with the legitimate FHIR server are added to the HTTP request headers.
7.  The `SimpleHTTPClient` sends the HTTP request, including the stolen authentication tokens, to the attacker-controlled server.
8.  The attacker captures the request and extracts the authentication tokens, potentially gaining unauthorized access to FHIR resources or registries.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to steal authentication tokens configured for legitimate FHIR servers. This credential theft can lead to a variety of impacts. First, the stolen credentials can be used to compromise FHIR package registries, potentially enabling supply chain attacks where malicious FHIR packages are distributed to downstream consumers. Second, if the stolen credentials grant access to protected FHIR endpoints, patient health records and other sensitive data could be exposed, leading to data breaches and regulatory consequences. Finally, the compromised validator service can indirectly impact the security of external FHIR registries, package servers and other systems.

## Recommendation

*   Upgrade to FHIR Validator version 6.9.4 or later to patch CVE-2026-34361 and address the SSRF vulnerability.
*   Deploy the Sigma rule `DetectSuspiciousFHIRValidatorLoadIG` to monitor for exploitation attempts targeting the `/loadIG` endpoint.
*   Implement network monitoring to detect outbound connections from the FHIR Validator to suspicious or unexpected domains, using the IOC `https://packages.fhir.org.attacker.com/malicious-ig` as a starting point.
*   Review and harden the configuration of FHIR server authentication within `fhir-settings.json`, minimizing the use of URL prefixes and employing more robust authentication mechanisms where possible.
