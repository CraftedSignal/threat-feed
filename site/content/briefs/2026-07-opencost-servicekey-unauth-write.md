---
title: OpenCost ServiceKey Endpoint Unauthorized Credential Overwrite/Injection Vulnerability
slug: 2026-07-opencost-servicekey-unauth-write
description: OpenCost contains an unauthenticated file write vulnerability, tracked as GHSA-wmj8-9953-vff5, in its `/serviceKey` endpoint that allows remote attackers to overwrite the GCP service account key file (`key.json`) without any authentication or input validation, leading to service disruption, credential theft, and potential privilege escalation within Kubernetes clusters or GCP environments.
date: "2026-07-14T19:25:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - opencost
  - kubernetes
  - cloud
  - gcp
  - vulnerability
  - unauthenticated-access
  - file-write
vendors:
  - OpenCost
products:
  - 'OpenCost: All versions'
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenCost contains an unauthenticated file write vulnerability in the `/serviceKey` endpoint that allows remote attackers to overwrite the GCP service account key file without authentication.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attacker can overwrite GCP service account key file content
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Malicious Credential Injection for Data Hijacking... OpenCost uses attacker's credentials to send requests to GCP Billing API
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Scenario 1: GCP Credential Overwrite Leading to Service Disruption... Cost Monitoring Disruption'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wmj8-9953-vff5
iocs:
  - type: url
    value: http://opencost.opencost.svc.cluster.local:9003/serviceKey
  - type: url
    value: http://localhost:9003/serviceKey
ioc_counts:
  url: 2
rules:
  - title: Detect OpenCost ServiceKey Unauthorized File Write Attempt
    description: Detects exploitation of OpenCost unauthorized file write vulnerability (GHSA-wmj8-9953-vff5) via unauthenticated HTTP POST requests to the /serviceKey endpoint. This indicates an attempt to overwrite the GCP service account key file.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - impact
      - initial_access
    techniques:
      - T1190
      - T1499
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

OpenCost, an open-source project for Kubernetes cost monitoring, is affected by an unauthenticated file write vulnerability (GHSA-wmj8-9953-vff5) in its `/serviceKey` endpoint. This flaw permits remote attackers to overwrite the `key.json` file, which typically stores Google Cloud Platform (GCP) service account credentials, without any form of authentication or input validation. The vulnerability resides within the `AddServiceKey` function in `pkg/costmodel/router.go`, where user-supplied content from a POST request's `key` parameter is directly written to the file system. This allows attackers to inject invalid data, causing service disruption by breaking GCP integrations, or to replace legitimate credentials with attacker-controlled ones, facilitating credential theft and potential privilege escalation within the targeted Kubernetes cluster or associated GCP environment. Additionally, an overly permissive CORS header (`Access-Control-Allow-Origin: *`) in the affected endpoint further enables cross-origin attacks if the OpenCost instance is exposed to a web browser. All versions of OpenCost up to and including the latest release are affected.

## Attack Chain

1. An attacker identifies a network-accessible OpenCost instance running a vulnerable version. This could be through a public ingress, NodePort exposure, or internal network access.
2. The attacker crafts an HTTP POST request targeting the `/serviceKey` endpoint of the OpenCost service (e.g., `http://opencost.opencost.svc.cluster.local:9003/serviceKey` or `http://localhost:9003/serviceKey`).
3. The request includes a `key` parameter within the request body, containing malicious data such as malformed JSON, an empty string, or attacker-controlled valid GCP service account credentials.
4. The vulnerable `AddServiceKey` function in OpenCost's `pkg/costmodel/router.go` receives the unauthenticated request.
5. Lacking any authentication or input validation, OpenCost extracts the value from the `key` parameter.
6. The extracted content is directly written to the `key.json` file located in the `CONFIG_PATH` directory (which defaults to `/var/configs`).
7. The existing `key.json` file is overwritten with the attacker-supplied malicious content, compromising the integrity or confidentiality of the GCP service account key.
8. Subsequent attempts by OpenCost to interact with GCP APIs will either fail due to invalid credentials, causing service disruption, or connect to an attacker-controlled GCP project, enabling data exfiltration or unauthorized actions.

## Impact

The unauthorized file write vulnerability in OpenCost can lead to severe consequences across multiple dimensions. If an attacker injects invalid JSON or malformed credentials into `key.json`, OpenCost's ability to communicate with the GCP Billing API will cease, resulting in a disruption of cost monitoring and FinOps processes. This directly impacts an organization's ability to track and manage cloud expenditures. More critically, an attacker can inject their own GCP service account credentials, leading to sensitive data leakage. This includes the organization's cloud resource usage patterns, detailed cost breakdowns per namespace, and overall business intelligence regarding infrastructure scale and technology adoption. Such information could be highly valuable to competitors or for reconnaissance in future attacks. While the attacker cannot control the file path or name, the ability to fully control the `key.json` content without authentication poses a significant risk. For improperly exposed instances, the permissive CORS configuration enables cross-origin attacks, allowing malicious websites to initiate attacks from a victim's browser without their awareness.

## Recommendation

* Deploy the Sigma rule `Detect OpenCost ServiceKey Unauthorized File Write Attempt` to your SIEM to alert on suspicious unauthenticated POST requests to the `/serviceKey` endpoint.
* Monitor `webserver` logs for HTTP POST requests directed at the `/serviceKey` endpoint, especially those originating from unexpected IP addresses or lacking proper authentication headers.
* Restrict network access to the OpenCost service endpoint `/serviceKey` through firewall rules, network policies, or API gateways to prevent unauthenticated external access.
* If possible, implement an authentication layer (e.g., API key, OAuth, OIDC) for the `/serviceKey` endpoint, as recommended by the OpenCost maintainers' remediation guidance.
* Ensure strong input validation is applied to the `key` parameter to verify the integrity and format of any submitted GCP service account keys.
* Review and restrict the `Access-Control-Allow-Origin` header in your web server or ingress configuration for OpenCost to only trusted domains, preventing cross-origin attacks.
