---
brief_id: brief-2026-11-16-github-payment-removal
event_id: brief-2026-11-16-github-payment-removal
revision: 1
activity_at: "2026-11-16T17:21:23Z"
title: GitHub Payment Method Removed
slug: 2026-11-github-payment-removal
description: An adversary with billing-manager, organization owner, or enterprise owner access can delete a payment instrument from a GitHub organization or enterprise to disrupt paid services, potentially leading to feature downgrades and repository suspension.
date: "2026-11-16T17:21:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  likelihood: likely
tags:
  - Cloud
  - SaaS
  - GitHub
  - Impact
vendors:
  - GitHub
products:
  - GitHub Enterprise
  - GitHub Organization
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Adversaries with billing-manager or owner access can delete a payment instrument to disrupt the organization's paid plan, which can lead to downgraded features, suspended private repositories, and loss of access to paid capabilities.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_github_payment_method_removed.toml
  - https://docs.github.com/en/billing/how-tos/set-up-payment/manage-payment-info
rules:
  - title: GitHub Payment Method Removed
    description: Identifies the removal of a payment method from a GitHub organization or enterprise, which can be an attempt by an adversary to disrupt paid plans.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - webserver
      - github
rules_count: 1
---

## Overview
The `payment_method.remove` audit action is logged in GitHub when a billing manager, organization owner, or enterprise owner removes a payment method from an organization or enterprise. This action is considered high-privilege.

## Attack Chain
An adversary with sufficient privileges (billing-manager or owner) can delete a payment instrument. This action may be used to disrupt an organization's paid plan, potentially as part of an extortion attempt, account takeover, or to obscure fraudulent billing changes.

## Impact
Disruption of the organization's paid plan can lead to downgraded features, suspended private repositories, and loss of access to paid capabilities.

## Recommendation
- Verify whether the removal of a payment method was authorized by checking with finance or billing owners.
- Correlate the `payment_method.remove` event with other logs, such as actor identity, `github.actor_ip`, `github.hashed_token`, and `github.programmatic_access_type`.
- Review audit logs for related events such as additional payment changes, plan downgrades, or owner modifications that may indicate unauthorized access or account takeover.
- If the removal is confirmed as unauthorized, revoke the associated token and ensure appropriate reauthentication.
