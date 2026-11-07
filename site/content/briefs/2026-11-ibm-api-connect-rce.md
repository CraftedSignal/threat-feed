---
brief_id: brief-2026-11-07-ibm-api-connect-rce
event_id: brief-2026-11-07-ibm-api-connect-rce
revision: 1
activity_at: "2026-11-07T05:50:12Z"
title: 'IBM API Connect: Remote code execution via object attribute modification (CVE-2026-17117)'
slug: 2026-11-ibm-api-connect-rce
description: An improper control of object attributes in IBM API Connect allows a remote authenticated attacker to modify system-reserved fields, leading to arbitrary code execution.
date: "2026-11-07T05:50:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
tags:
  - cve-2026-17117
  - rce
  - ibm
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote authenticated attacker to execute arbitrary code due to improperly controlled modification of object attributes.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability... could lead to code execution.
    confidence_band: high
cves:
  - id: CVE-2026-17117
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17117
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all instances of IBM API Connect and verify current versioning against the vulnerability range.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable version ranges defined in CVE-2026-17117.
  hunt_leads:
    - lead: Identify authenticated sessions performing unusual configuration changes or POST/PUT requests to object management endpoints.
      technique_id: T1190
      data_needed:
        - API Connect application audit logs
        - Administrative access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attack requires authenticated remote modification of object attributes.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches provided by IBM as soon as they become available for the identified affected versions.
      owner: IT Operations
      addresses: CVE-2026-17117
      evidence: Vulnerability remediation requires software update.
---

CVE-2026-17117 is a vulnerability in IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2. The flaw allows an authenticated remote user to manipulate object attributes that are intended to be restricted to system use. Successful exploitation enables the execution of arbitrary code within the context of the affected application.

## Impact
Successful exploitation allows for remote code execution by authenticated users, potentially leading to full system compromise of the API Connect instance.

## Recommendation
- Inventory IBM API Connect instances to identify versions within the 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2 ranges.
- Review IBM security bulletins for the release of fixed firmware or software updates and prioritize patching of internet-facing instances.
- Monitor authentication logs for suspicious administrative activity or unauthorized API call patterns targeting object configuration endpoints.
