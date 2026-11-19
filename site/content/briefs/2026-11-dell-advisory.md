---
brief_id: brief-2026-11-19-dell-advisory
event_id: brief-2026-11-19-dell-advisory
revision: 1
activity_at: "2026-11-19T16:42:17Z"
title: 'Dell Infrastructure Management Tools: Multiple Security Vulnerabilities'
slug: 2026-11-dell-advisory
description: Dell has released security updates addressing multiple vulnerabilities across various infrastructure management tools including Ansible modules, Terraform providers, and storage management software.
date: "2026-11-19T16:42:17Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: All information is sourced directly from the official Dell security advisory and the Canadian Centre for Cyber Security.
tags:
  - informational
  - product-news
vendors:
  - Dell
products:
  - Ansible Storage for PowerFlex
  - Ansible Storage for PowerStore
  - Ansible Storage for Unity
  - OpenManage Ansible Modules
  - PowerScale InsightIQ
  - PowerStore 5000T
  - Terraform Provider for PowerFlex
  - Terraform Provider for PowerStore
product_versions:
  - product: Ansible Storage for PowerFlex
    range: < 3.2.0
  - product: Ansible Storage for PowerStore
    range: < 3.9.0
  - product: Ansible Storage for Unity
    range: < 1.2.13
  - product: OpenManage Ansible Modules
    range: < 11.0.0
  - product: PowerScale InsightIQ
    range: < 6.4.1
  - product: PowerStore 5000T
    range: < 5.1.0.0-2798105
  - product: Terraform Provider for PowerFlex
    range: < 1.9.0
  - product: Terraform Provider for PowerStore
    range: < 1.3.1
references:
  - https://cyber.gc.ca/en/alerts-advisories/dell-security-advisory-av26-1161
  - https://www.dell.com/support/kbdoc/en-us/000527640/dsa-2026-479-dell-powerstore-t-security-update-for-multiple-vulnerabilities
  - https://www.dell.com/support/kbdoc/en-gb/000528934/dsa-2026-480-security-update-for-dell-powerscale-insightiq-multiple-vulnerabilities
  - https://www.dell.com/support/kbdoc/en-in/000515434/dsa-2026-433-security-update-for-dell-terraform-provider-for-dell-storage-multiple-vulnerabilities
  - https://www.dell.com/support/kbdoc/en-au/000515361/dsa-2026-431-security-update-for-dell-ansible-storage-multiple-vulnerabilities
  - https://www.dell.com/support/kbdoc/en-ca/000515420/dsa-2026-432-security-update-for-dell-ansible-server-vulnerabilities
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: short_term
      action: Patch affected Dell infrastructure management software to the specified version levels.
      owner: IT Operations
      addresses: Multiple Dell storage management components
      evidence: Dell security advisories (AV26-1161) provided via CCSE.
---

## Overview

Dell has published a series of security advisories addressing multiple vulnerabilities in its infrastructure management software suite. The affected products include Ansible modules for PowerFlex, PowerStore, and Unity; OpenManage Ansible Modules; PowerScale InsightIQ; PowerStore 5000T; and Terraform providers for PowerFlex and PowerStore. These updates mitigate risks associated with multiple unspecified vulnerabilities across these platforms.

## Recommendation

Administrators should inventory all deployed instances of the affected software and apply the specified updates provided in the linked Dell support documentation to secure their environments:

- Update Ansible Storage for PowerFlex to version 3.2.0 or later.
- Update Ansible Storage for PowerStore to version 3.9.0 or later.
- Update Ansible Storage for Unity to version 1.2.13 or later.
- Update OpenManage Ansible Modules to version 11.0.0 or later.
- Update PowerScale InsightIQ to version 6.4.1 or later.
- Update PowerStore 5000T to version 5.1.0.0-2798105 or later.
- Update Terraform Provider for PowerFlex to version 1.9.0 or later.
- Update Terraform Provider for PowerStore to version 1.3.1 or later.
