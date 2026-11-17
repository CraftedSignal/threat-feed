---
brief_id: brief-2026-11-17-atlassian-improper-auth
event_id: brief-2026-11-17-atlassian-improper-auth
revision: 1
activity_at: "2026-11-17T21:15:38Z"
title: 'Atlassian Jira Service Management: Improper Authorization Vulnerability'
slug: 2026-11-atlassian-improper-auth
description: Atlassian disclosed an improper authorization vulnerability affecting various versions of Jira Service Management Data Center and Server, necessitating immediate review and update of affected installations.
date: "2026-11-17T21:15:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Content verified against the provided CCCS alert and Atlassian advisory link references.
tags:
  - vulnerability
  - atlassian
  - jira
  - authentication
vendors:
  - Atlassian
products:
  - Jira Service Management Data Center
  - Jira Service Management Server
product_versions:
  - product: Jira Service Management Data Center
    range: <= 10.3.27, <= 11.3.13
  - product: Jira Service Management Server
    range: 5.12.16 to 5.12.42
references:
  - https://cyber.gc.ca/en/alerts-advisories/atlassian-security-advisory-av26-1166
  - https://jira.atlassian.com/browse/JSDSERVER-16936
  - https://www.atlassian.com/trust/security/advisories
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all Jira Service Management Server and Data Center installations.
      owner: IT Operations
      due: 48h
      evidence: Advisory notes specific version ranges for both product variants.
    - action: Subscribe to Atlassian Security Advisory updates for JSDSERVER-16936.
      owner: Security Operations
      due: 24h
      evidence: Vendor advisory portal link provided.
  enrichment_needed:
    - item: JSDSERVER-16936
      owner: CTI
      reason: Verify if the improper authorization allows unauthenticated access or requires low-privilege escalation.
      evidence: The provided source does not explicitly state the authentication requirements for the vulnerability.
  mitigation_plan:
    - priority: short_term
      action: Apply official patches provided by Atlassian once verified for the specific instance version.
      owner: IT Operations
      addresses: Jira Service Management vulnerability JSDSERVER-16936
      evidence: Official guidance encourages administrators to apply updates as they become available.
---

## Overview

On November 17, 2026, the Canadian Centre for Cyber Security (CCCS) issued an advisory regarding an improper authorization vulnerability in Atlassian Jira Service Management. The vulnerability, tracked as JSDSERVER-16936, affects specific versions of Jira Service Management Data Center and Server. Atlassian has provided documentation for the issue through their security advisory portal, and administrators are urged to review the vendor's guidance for specific remediation steps and available security updates.

## Recommendation

- Inventory all Jira Service Management Data Center and Server instances to identify if they are running the affected versions listed.
- Regularly monitor the Atlassian Security Advisories portal for specific patch releases corresponding to JSDSERVER-16936.
- Apply available vendor updates to vulnerable installations as soon as they are published by Atlassian.
