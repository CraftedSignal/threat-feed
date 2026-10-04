---
title: Improper Certificate Validation in go-micro
slug: 2026-10-go-micro-tls
description: The go-micro library versions prior to 6.0.0 insecurely configure TLS validation by default, enabling man-in-the-middle attacks to intercept traffic and harvest credentials.
date: "2026-10-04T18:54:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:go-micro:go-micro:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - tls
  - mitm
  - go-micro
vendors:
  - go-micro
products:
  - go-micro (< 6.0.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Man-in-the-middle attackers can present any certificate to intercept or modify gRPC transport, HTTP and RabbitMQ broker, and Consul or etcd registry traffic, including authentication tokens and credentials.
    confidence_band: high
cves:
  - id: CVE-2026-105216
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105216
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade go-micro dependencies to version 6.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-105216 remediation requires upgrading to 6.0.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade go-micro components to version 6.0.0
      owner: IT Operations
      addresses: CVE-2026-105216
      evidence: NVD vulnerability notice
---

The go-micro framework versions before 6.0.0 contain a critical vulnerability where the shared TLS helper defaults the InsecureSkipVerify configuration to true. This default setting bypasses standard X.509 certificate validation, allowing network-adjacent attackers to perform man-in-the-middle (MitM) attacks. By positioning themselves between microservices or between a service and its broker/registry, an attacker can silently intercept, inspect, or modify traffic. The impact is significant, as the vulnerability affects critical communication channels including gRPC, HTTP, RabbitMQ broker traffic, and service registry interactions with Consul or etcd. Successful exploitation provides attackers with the capability to steal authentication tokens and administrative credentials, facilitating further lateral movement or data exfiltration within the microservices environment.

## Impact

Successful exploitation of CVE-2026-105216 allows attackers to compromise the confidentiality and integrity of inter-service communication. This vulnerability facilitates the theft of sensitive authentication credentials and tokens, leading to potential unauthorized access to the entire backend infrastructure or associated data stores. Organizations utilizing go-micro in distributed environments are at risk of complete service impersonation and data interception.

## Recommendation

Prioritized actions for addressing CVE-2026-105216:

- Update all deployments of go-micro to version 6.0.0 or later to ensure InsecureSkipVerify is not enabled by default.
- Review all custom service implementations to verify that InsecureSkipVerify is explicitly set to false when configuring TLS clients.
- Monitor network traffic logs for unexpected TLS certificate mismatches or unusual gRPC/HTTP traffic patterns directed toward service registries and message brokers.
