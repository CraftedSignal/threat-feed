---
title: CVE-2026-18212 Keycloak Denial of Service via SAML Redirect Binding
slug: 2026-09-keycloak-saml-dos
description: An unauthenticated attacker can trigger a denial of service in Keycloak by sending repeated malformed SAML requests that cause native memory exhaustion due to improper zlib memory management.
date: "2026-09-16T15:50:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated attacker can exploit this by sending repeated malformed SAML requests, leading to native memory exhaustion and a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-18212
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18212
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and monitor Keycloak logs for excessive SAML processing errors or spikes in malformed requests.
      owner: SOC
      due: 24h
      evidence: CVE-2026-18212 description of repeated malformed SAML requests.
  mitigation_plan:
    - priority: immediate
      action: Identify current Keycloak version and monitor Red Hat Security Advisories for the specific patch remediating CVE-2026-18212.
      owner: IT Operations
      addresses: CVE-2026-18212
      evidence: NVD vulnerability disclosure.
---

CVE-2026-18212 describes a memory management vulnerability within the SAML Redirect Binding implementation of Keycloak. The defect resides in the application's custom DEFLATE compression and decompression helpers, which fail to correctly release native zlib memory after processing SAML payloads. Because this logic is executed during the handling of incoming SAML Redirect Binding requests, it is accessible to unauthenticated remote users. By repeatedly sending specially crafted or malformed SAML requests that trigger this compression routine, an attacker can induce a steady accumulation of native memory usage, eventually leading to exhaustion of the Java Virtual Machine (JVM) native memory. This results in a persistent denial of service condition for the affected Keycloak instance.

## Impact

Successful exploitation results in a complete denial of service for the Keycloak identity provider, preventing users from authenticating to any downstream applications or services integrated with the identity manager. This affects availability for organizations relying on Keycloak for Single Sign-On (SSO) and identity federation.

## Recommendation

Prioritize monitoring for anomalous spikes in SAML authentication traffic or high rates of malformed HTTP requests targeting SAML endpoints. Ensure Keycloak instances are updated to the vendor-provided patch version (when available) that remediates the native zlib memory leak. Monitor system-level metrics (e.g., resident set size and native memory allocation) for the Keycloak process to detect memory exhaustion patterns indicative of exploitation.
