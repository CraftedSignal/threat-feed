---
title: OpenShift Router SSRF via FQDN EndpointSlice (CVE-2026-42965)
slug: 2026-05-openshift-router-ssrf
description: CVE-2026-42965 describes a server-side request forgery (SSRF) vulnerability in the OpenShift Router where a user with EndpointSlice write access can expose instance credentials by creating a service that proxies requests to a cloud metadata endpoint.
date: "2026-05-29T11:18:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - cve
  - openshift
vendors:
  - Red Hat
products:
  - OpenShift Router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-42965
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42965
  - https://access.redhat.com/security/cve/CVE-2026-42965
  - https://bugzilla.redhat.com/show_bug.cgi?id=2483184
rules:
  - title: Detect OpenShift Router Connecting to Cloud Metadata Endpoint
    description: Detects CVE-2026-42965 exploitation - OpenShift Router making network connections to common cloud metadata endpoints.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

CVE-2026-42965 describes a server-side request forgery (SSRF) vulnerability in the OpenShift Router. This flaw allows a user with EndpointSlice write access to exploit the vulnerability by creating a Service backed by a Fully Qualified Domain Name (FQDN) EndpointSlice that resolves to a cloud metadata endpoint. The OpenShift Router will then proxy requests to the cloud metadata endpoint. This leads to the disclosure of sensitive information, specifically instance credentials and other metadata. This bypasses previous security measures designed to validate IP addresses.

## Attack Chain

1. An attacker gains unauthorized EndpointSlice write access within the OpenShift environment.
2. The attacker crafts a malicious EndpointSlice.
3. The crafted EndpointSlice contains a Fully Qualified Domain Name (FQDN).
4. The FQDN resolves to a cloud metadata endpoint (e.g., `169.254.169.254` on AWS).
5. The attacker creates a Service that utilizes the malicious EndpointSlice.
6. The OpenShift Router receives requests destined for the created Service.
7. The router proxies these requests to the cloud metadata endpoint specified in the FQDN.
8. The cloud metadata endpoint responds with sensitive data, which is then returned to the attacker, exposing instance credentials and other metadata.

## Impact

Successful exploitation of CVE-2026-42965 allows an attacker with EndpointSlice write access to gain access to sensitive information residing within the cloud metadata service. This may include instance credentials, API keys, and other data that can be used to further compromise the OpenShift environment and the underlying cloud infrastructure. The number of affected systems is dependent on the permissions granted and the cloud infrastructure.

## Recommendation

*   Apply available patches or updates for the OpenShift Router provided by Red Hat to remediate CVE-2026-42965.
*   Implement strict access controls and RBAC (Role-Based Access Control) policies to limit EndpointSlice write access to only authorized users and service accounts.
*   Monitor for unusual network activity and DNS queries originating from the OpenShift Router that target cloud metadata endpoints.
*   Deploy the Sigma rule that detects connections to common cloud metadata endpoints from the OpenShift Router to identify potential exploitation attempts.
