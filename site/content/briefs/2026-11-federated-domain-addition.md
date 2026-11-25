---
brief_id: brief-2026-11-10-federated-domain-addition
event_id: brief-2026-11-10-federated-domain-addition
revision: 2
activity_at: "2026-11-25T16:19:05Z"
revision_history:
  - revision: 2
    at: "2026-11-25T16:19:05Z"
    checksum: sha256:52efa76a81c4f663dbb7b121a1157505a221d558471f31478a3869181b3a5123
    summary: new product
    changed_fields:
      - affected_products
      - affected_vendors
      - lastmod
      - updates
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml
title: 'Microsoft 365: Federated domain creation'
slug: 2026-11-federated-domain-addition
description: Monitoring for the addition of new federated domains in Microsoft 365, a technique associated with persistent unauthorized access and SAML-based identity provider manipulation.
date: "2026-11-10T03:34:06Z"
lastmod: "2026-11-25T16:18:38Z"
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
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Metadata verified against provided documentation
tags:
  - persistence
  - identity
  - m365
  - cloud-security
vendors:
  - Microsoft
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.003
    subtechnique_name: Cloud Account
    evidence: The addition of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities.
    confidence_band: high
references:
  - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
  - https://us-cert.cisa.gov/ncas/alerts/aa21-008a
  - https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
  - https://o365blog.com/post/aadbackdoor/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml
rules:
  - title: Detect Addition of New Federated Domain
    description: Detects the successful addition of a new federated domain, which may indicate unauthorized identity persistence
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - m365
      - exchange
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for Add-FederatedDomain
      owner: Detection Engineering
      due: 48h
      evidence: Source defines Add-FederatedDomain as a key indicator of identity persistence
  hunt_leads:
    - lead: Review audit logs for all Add-FederatedDomain events in the last 90 days
      technique_id: T1136.003
      data_needed:
        - M365 Unified Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Federated domain creation is a high-impact configuration change
updates:
  - at: "2026-11-25T16:18:38Z"
    level: L1
    summary: new product
    sources:
      - sigma-hq
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/exchange/microsoft365_new_federated_domain_added_exchange.yml
---

## Overview

The addition of a new federated domain in Microsoft 365 environment represents a significant configuration change that may indicate identity-based persistence or backdoor activity. Adversaries with administrative access can leverage federation to bypass standard authentication controls, a technique historically documented in campaigns involving SAML token manipulation.

## Impact

Legitimate domain federation is a routine administrative task, but unauthorized modification of federation settings provides an attacker with the ability to issue identity tokens, effectively bypassing multi-factor authentication and maintaining long-term access to the target cloud environment.

## Recommendation

- Implement monitoring for the 'Add-FederatedDomain' event within M365 Exchange audit logs to identify unauthorized federation changes.
- Establish a formal change management process for federation configurations and audit these changes periodically against authorized provisioning activity.
- Deploy the provided detection rule to alert on all instances of domain federation additions for manual investigation.
