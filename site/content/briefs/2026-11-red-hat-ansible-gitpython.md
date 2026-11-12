---
brief_id: brief-2026-11-12-red-hat-ansible-gitpython
event_id: brief-2026-11-12-red-hat-ansible-gitpython
revision: 1
activity_at: "2026-11-12T16:16:43Z"
title: 'Red Hat Ansible Automation Platform: Multiple vulnerabilities in GitPython'
slug: 2026-11-red-hat-ansible-gitpython
description: Red Hat Ansible Automation Platform is affected by multiple vulnerabilities in the integrated GitPython library that allow a remote, unauthenticated attacker to execute arbitrary code, disclose local files, or trigger a denial-of-service condition.
date: "2026-11-12T16:16:43Z"
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
  verdict: pass_with_fixes
  validation_status: Waiting for official vendor CVE release and patch availability
tags:
  - vulnerability
  - rce
  - denial-of-service
  - information-disclosure
vendors:
  - Red Hat
products:
  - Ansible Automation Platform
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4532
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Perform inventory of all Red Hat Ansible Automation Platform instances.
      owner: IT Operations
      due: 48h
      evidence: Inventory is required to assess vulnerability exposure surface.
  enrichment_needed:
    - item: CVE Identifiers
      owner: CTI
      reason: Source does not list specific CVE IDs; these are needed to correlate with threat intel feeds.
      evidence: Source material mentions vulnerabilities but lacks CVE enumeration.
  hunt_leads:
    - lead: Investigate unauthorized remote connection attempts to Ansible Automation Platform management ports.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Firewall logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Remote unauthenticated exploitation is possible.
---

Red Hat Ansible Automation Platform is affected by multiple vulnerabilities originating from its dependency on the GitPython library. These vulnerabilities permit an unauthenticated remote attacker to achieve arbitrary code execution, conduct unauthorized local file disclosure, and trigger a denial-of-service (DoS) condition. As of the current advisory, specific CVE identifiers have not been disclosed, and the extent of the vulnerability remains limited to the documented impacts.

## Impact
Successful exploitation may lead to full system compromise through arbitrary code execution, loss of confidentiality via unauthorized file disclosure, or service interruption through a DoS condition.

## Recommendation
- Inventory all deployments of Red Hat Ansible Automation Platform within the organization.
- Monitor official Red Hat security advisories for the release of patches specifically addressing GitPython-related vulnerabilities.
- Restrict access to management interfaces for Ansible Automation Platform to trusted networks to reduce the exposure to unauthenticated remote attackers.
