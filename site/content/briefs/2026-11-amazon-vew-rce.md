---
brief_id: brief-2026-11-02-amazon-vew-rce
event_id: brief-2026-11-02-amazon-vew-rce
revision: 1
activity_at: "2026-11-02T19:49:34Z"
title: 'Amazon Virtual Engineering Workbench: Arbitrary code execution via template engine (CVE-2026-119085)'
slug: 2026-11-amazon-vew-rce
description: An improper neutralization vulnerability in the Amazon Virtual Engineering Workbench publishing component allows authenticated remote attackers to execute arbitrary code via crafted CloudFormation templates.
date: "2026-11-02T19:49:34Z"
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
  validation_status: Source verified; remediation steps require environment-specific deployment
cpes:
  - cpe:2.3:a:amazon:virtual_engineering_workbench:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-security
  - code-execution
vendors:
  - Amazon
products:
  - Virtual Engineering Workbench
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The code is reachable through a crafted CloudFormation template body containing template engine directives submitted through the product versioning API.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote authenticated third party to run arbitrary code with the permissions of the publishing Lambda's IAM role.
    confidence_band: high
cves:
  - id: CVE-2026-119085
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119085
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Redeploy Amazon Virtual Engineering Workbench from the latest version in the awslabs repository
      owner: IT Operations
      due: 24h
      evidence: To remediate this issue, users should redeploy from the latest version of awslabs/virtual-engineering-workbench.
  hunt_leads:
    - lead: Monitor CloudTrail logs for calls to the product versioning API containing CloudFormation templates with unusual syntax or template directives
      technique_id: T1190
      data_needed:
        - AWS CloudTrail
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The code is reachable through a crafted CloudFormation template body containing template engine directives submitted through the product versioning API.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest version of Virtual Engineering Workbench
      owner: IT Operations
      addresses: CVE-2026-119085
      evidence: To remediate this issue, users should redeploy from the latest version of awslabs/virtual-engineering-workbench.
---

Amazon Virtual Engineering Workbench (VEW) contains a vulnerability (CVE-2026-119085) in the template engine used within its publishing component. The flaw allows a remote authenticated user to supply a crafted CloudFormation template body containing malicious template engine directives through the product versioning API. Successful exploitation results in arbitrary code execution with the permissions of the publishing Lambda function's IAM role, potentially enabling unauthorized access to data and resources across all tenant projects.

## Impact
Successful exploitation allows for arbitrary code execution with the privileges of the AWS Lambda IAM role associated with the publishing component. This may result in unauthorized access, modification, or exfiltration of sensitive data and resources across all tenant projects within the affected environment.

## Recommendation
- Upgrade the Amazon Virtual Engineering Workbench deployment immediately by redeploying from the latest version available in the awslabs/virtual-engineering-workbench repository.
- Review IAM permissions associated with the publishing Lambda function to ensure the principle of least privilege is applied, limiting the impact of potential code execution.
- Audit logs for the product versioning API for requests containing unusual CloudFormation template bodies or template engine directive patterns.
