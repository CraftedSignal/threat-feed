---
brief_id: brief-2026-11-16-github-org-transfer
event_id: brief-2026-11-16-github-org-transfer
revision: 1
activity_at: "2026-11-16T17:21:34Z"
title: 'GitHub Enterprise: Unauthorized organization removal or transfer'
slug: 2026-11-github-org-transfer
description: An attacker with enterprise owner privileges can remove or transfer a GitHub organization to bypass centralized security controls, disrupt audit logging, or exfiltrate intellectual property.
date: "2026-11-16T17:21:34Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced from verified Elastic detection rules repository
tags:
  - cloud
  - saas
  - github
  - defense-evasion
  - exfiltration
  - impact
vendors:
  - GitHub
products:
  - GitHub Enterprise
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: An adversary with enterprise owner access can use either action to move intellectual property beyond the organization's visibility or to disrupt the enterprise's governance and security controls.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: Removing an organization takes its repositories, members, audit history, and billing out of the enterprise's centralized management and security monitoring.
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: a transfer hands the organization and its repositories to a different enterprise or owner.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_github_organization_removed_or_transferred.toml
  - https://docs.github.com/en/enterprise-cloud@latest/admin/managing-organizations-in-your-enterprise/adding-organizations-to-your-enterprise
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security Team
  hunt_leads:
    - lead: Identify suspicious organization transfers or removals by monitoring GitHub audit logs for business.remove_organization, org.transfer_outgoing, or org.transfer events.
      technique_id: T1562.001
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This rule fires on business.remove_organization, which removes an organization from the enterprise, and on org.transfer_outgoing / org.transfer, which move an organization to a different enterprise or owner.
---

## Overview
Unauthorized removal or transfer of a GitHub organization represents a significant risk to enterprise governance. When an organization is removed from an enterprise using the `business.remove_organization` action, or transferred to another enterprise/owner using `org.transfer_outgoing` or `org.transfer`, it is effectively disconnected from the parent enterprise's centralized audit logging, security policies, and management monitoring. An attacker holding enterprise owner permissions can abuse these features to hide malicious activity or migrate entire repositories to an actor-controlled environment.

## Impact
Successful execution of these actions results in the immediate loss of visibility into repository activity, member access, and billing logs. Transfers allow for the potential exfiltration of intellectual property by moving entire organizations beyond the scope of existing security controls.

## Recommendation
- Deploy detection coverage for the identified GitHub audit log events to enable near real-time alerting on organization-level changes.
- Establish a strict change management workflow requiring multi-party authorization for any organization removal or transfer request.
- Audit the current list of Enterprise Owners to ensure the principle of least privilege is applied.
- Regularly review audit logs for anomalous activity by enterprise-privileged accounts, specifically looking for sequences of organization removals following account takeover or unusual API usage.
