---
brief_id: brief-2026-10-28-monai-rce-c321a0ee
event_id: brief-2026-10-28-monai-rce-c321a0ee
revision: 1
activity_at: "2026-10-28T20:38:59Z"
title: 'MONAI: Remote Code Execution via logging configuration (CVE-2026-118683)'
slug: 2026-10-monai-rce-c321a0ee
description: An insecure call to eval() within the MONAI ConfigWorkflow.__init__ method allows for remote code execution when a victim loads a malicious bundle containing a crafted logging.conf file.
date: "2026-10-28T20:38:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source identifies exact vulnerable method and function call path
cpes:
  - cpe:2.3:a:monai:monai:*:*:*:*:*:*:*:*
vendors:
  - MONAI
products:
  - MONAI (1.2.0 - 1.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can publish a malicious bundle whose logging.conf runs arbitrary Python at workflow construction when a victim loads or runs the bundle.
    confidence_band: high
cves:
  - id: CVE-2026-118683
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118683
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade MONAI to 1.6.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-118683 patch availability
  hunt_leads:
    - lead: Search for logging.conf files within MONAI bundle directories that define suspicious handler class or arguments
      technique_id: T1203
      data_needed:
        - File content inspection of bundle directories
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability arises because logging.config.fileConfig processes a bundle's configs/logging.conf file
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.6.1
      owner: IT Operations
      addresses: CVE-2026-118683
      evidence: NVD advisory
---

MONAI versions 1.2.0 through 1.6.0 are vulnerable to remote code execution (CVE-2026-118683). The vulnerability resides in the `ConfigWorkflow.__init__` method, which utilizes `logging.config.fileConfig` to process a bundle's `configs/logging.conf` file. This function insecurely evaluates the handler class and arguments fields using `eval()`, allowing attackers to execute arbitrary Python code when a bundle is loaded or initialized.

## Impact
Successful exploitation allows for arbitrary Python code execution under the context of the user or service running the MONAI workflow. This may lead to full system compromise depending on the privileges of the MONAI process.

## Recommendation
- Update all instances of MONAI to version 1.6.1 or later immediately.
- Implement strict validation of `logging.conf` files within bundles if an upgrade is not immediately possible.
- Scan existing model bundle repositories for `logging.conf` files that contain unconventional handler class or argument definitions.
