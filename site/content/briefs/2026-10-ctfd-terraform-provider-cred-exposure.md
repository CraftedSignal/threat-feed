---
brief_id: brief-2026-10-27-ctfd-terraform-provider-cred-exposure
event_id: brief-2026-10-27-ctfd-terraform-provider-cred-exposure
revision: 1
activity_at: "2026-10-27T23:59:06Z"
title: 'CTFer.io CTFd Terraform Provider: Sensitive credential exposure in state (CVE-2026-116683)'
slug: 2026-10-ctfd-terraform-provider-cred-exposure
description: The CTFer.io CTFd Terraform Provider fails to mark team passwords as sensitive, resulting in plain-text storage of credentials within Terraform state files (CVE-2026-116683).
date: "2026-10-27T23:59:06Z"
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
  validation_status: Verified against GHSA advisory
cpes:
  - cpe:2.3:a:ctfer.io:terraform-provider-ctfd:*:*:*:*:*:*:*:*
vendors:
  - CTFer.io
products:
  - terraform-provider-ctfd (0.1.5-1.1.0)
  - terraform-provider-ctfd/v2 (< 2.8.2)
cves:
  - id: CVE-2026-116683
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-vg84-c5mg-76xh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116683
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade terraform-provider-ctfd to v2.8.2 or later
      owner: IT Operations
      due: 48h
      evidence: Patched in v2.8.2.
  hunt_leads:
    - lead: Search CI/CD logs, version control systems, and state storage buckets for unencrypted team passwords associated with CTFd infrastructure
      data_needed:
        - Terraform state files (.tfstate)
        - CI/CD build logs containing Terraform output
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CTFer.io's CTFd Terraform Provider stores ctfd_team.password as non-sensitive values.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Terraform state storage locations to minimize the risk of unauthorized reads
      owner: Security Engineering
      addresses: CVE-2026-116683
      evidence: CTFer.io recommends you keep your state in safe environments with a limited set of users who can access it
---

The CTFer.io Terraform Provider for CTFd contains a vulnerability where the `ctfd_team.password` attribute is not marked as sensitive within the Terraform resource schema. This configuration causes Terraform to store these passwords in plain text within the state file (CWE-522). Any entity with read access to the state file can retrieve these credentials without requiring the state's encryption key. This affects version ranges 0.1.5 through 1.1.0 for the main provider and all versions prior to 2.8.2 for the v2 provider.

## Impact

Successful exploitation allows unauthorized access to team credentials stored in CTFd. Because Terraform state is often stored in version control systems or remote backends, exposure of these files could lead to widespread credential compromise.

## Recommendation

- Upgrade to terraform-provider-ctfd version 2.8.2 or later immediately.
- Audit existing Terraform state files for the `ctfd_team` resource and redact any plain-text passwords found.
- Enforce strict access control on Terraform state storage backends (e.g., S3 buckets, Terraform Cloud) to prevent unauthorized read access by users or automated processes.
