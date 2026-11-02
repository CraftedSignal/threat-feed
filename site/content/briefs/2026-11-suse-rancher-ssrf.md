---
brief_id: brief-2026-11-02-suse-rancher-ssrf
event_id: brief-2026-11-02-suse-rancher-ssrf
revision: 1
activity_at: "2026-11-02T21:21:52Z"
title: SUSE Rancher Meta Proxy Allowlist Bypass SSRF
slug: 2026-11-suse-rancher-ssrf
description: SUSE Rancher is vulnerable to a meta proxy allowlist bypass that results in server-side request forgery (SSRF), allowing potential unauthorized internal network requests.
date: "2026-11-02T21:21:52Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch versions validated against source advisory
tags:
  - vulnerability
  - ssrf
  - cloud
vendors:
  - SUSE
products:
  - Rancher (< 2.11.19)
  - Rancher (2.12.0 - 2.12.14)
  - Rancher (2.13.0 - 2.13.10)
  - Rancher (2.14.0 - 2.14.6)
  - Rancher (2.15.0 - 2.15.2)
references:
  - https://cyber.gc.ca/en/alerts-advisories/suse-linux-security-advisory-av26-1113
  - https://github.com/rancher/rancher/security/advisories/GHSA-f9gf-wh3x-jx3v
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Rancher deployments to the specified patched versions
      owner: IT Operations
      due: 48h
      evidence: Rancher vulnerability requires patching to address meta proxy allowlist bypass
  hunt_leads:
    - lead: Hunt for anomalous requests to internal metadata services (e.g., 169.254.169.254) or internal IP ranges originating from the Rancher server process
      technique_id: T1046
      data_needed:
        - Rancher container network logs
        - VPC/Cloud flow logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability leads to server-side request forgery
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade to patched versions: 2.11.19, 2.12.15, 2.13.11, 2.14.7, or 2.15.3'
      owner: IT Operations
      addresses: Meta proxy allowlist bypass SSRF
      evidence: Source advisory lists fixed version numbers
---

A security vulnerability exists in SUSE Rancher, specifically within its meta proxy component, which allows for an allowlist bypass. This vulnerability can lead to server-side request forgery (SSRF), potentially enabling attackers to make unauthorized requests to internal resources that should be restricted. Administrators should apply the provided updates immediately.

## Recommendation
- Update Rancher instances to the following patched versions to address the meta proxy allowlist bypass:
 - 2.11.19
 - 2.12.15
 - 2.13.11
 - 2.14.7
 - 2.15.3
- Review Rancher logs for anomalous outbound HTTP requests originating from the cluster management API or proxy components.
