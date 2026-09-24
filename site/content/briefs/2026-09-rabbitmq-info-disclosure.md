---
title: Information Disclosure Vulnerability in RabbitMQ
slug: 2026-09-rabbitmq-info-disclosure
description: An authenticated, remote attacker can exploit a vulnerability in RabbitMQ to perform unauthorized disclosure of sensitive information.
date: "2026-09-24T14:01:05Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ibm:financial_transaction_manager_for_multiplatform:*:*:*:*:*:swift_services:*:*
tags:
  - vulnerability
  - information-disclosure
vendors:
  - Broadcom
products:
  - RabbitMQ
cves:
  - id: CVE-2024-49339
    cvss: 6.4
    epss: 0.00223
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2254
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Upgrade RabbitMQ to the latest patched version provided by Broadcom
      owner: IT Operations
      addresses: CVE-2024-49339
      evidence: Source security advisory identifying a vulnerability in RabbitMQ.
---

A security vulnerability has been identified in RabbitMQ which allows a remote, authenticated attacker to gain unauthorized access to sensitive information. The flaw relates to CVE-2024-49339. Successful exploitation of this vulnerability could allow an attacker to bypass intended access controls and view data that should be restricted based on their privilege level. Defenders should review their RabbitMQ configurations and ensure all instances are updated to the vendor-provided security patches that address this specific vulnerability. As this requires prior authentication, organizations should also audit existing user permissions and restrict access to the RabbitMQ management interface to trusted internal networks.

## Impact

Successful exploitation results in the unauthorized disclosure of information held within the RabbitMQ environment. This impacts organizations relying on RabbitMQ for secure message queuing and data distribution, potentially exposing sensitive business logic or data payloads to authenticated users who should not have access.

## Recommendation

- Patch RabbitMQ to the latest version as recommended by the vendor to address CVE-2024-49339.
- Audit RabbitMQ user permissions to ensure the principle of least privilege is applied, mitigating the impact of an authenticated attacker.
- Restrict access to the RabbitMQ management API to authorized administrative subnets.
