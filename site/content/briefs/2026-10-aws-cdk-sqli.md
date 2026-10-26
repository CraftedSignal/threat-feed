---
brief_id: brief-2026-10-26-aws-cdk-sqli
event_id: brief-2026-10-26-aws-cdk-sqli
revision: 1
activity_at: "2026-10-26T19:44:40Z"
title: 'AWS Cloud Development Kit: SQL injection in @aws-cdk/aws-redshift-alpha (CVE-2026-115418)'
slug: 2026-10-aws-cdk-sqli
description: An SQL injection vulnerability in the @aws-cdk/aws-redshift-alpha module allows attackers to execute arbitrary SQL commands with superuser privileges on Amazon Redshift clusters by manipulating construct property values.
date: "2026-10-26T19:44:40Z"
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
  validation_status: Patch version verified against source.
cpes:
  - cpe:2.3:a:amazon:aws_cloud_development_kit:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - aws
  - cloud
vendors:
  - Amazon
products:
  - AWS Cloud Development Kit (@aws-cdk/aws-redshift-alpha < 2.274.0-alpha.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SQL injection in the database-query custom resource handlers... could allow a third party who can influence construct property values to run SQL statements
    confidence_band: high
cves:
  - id: CVE-2026-115418
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115418
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade @aws-cdk/aws-redshift-alpha to version 2.274.0-alpha.0 or later.
      owner: IT Operations
      due: 48h
      evidence: To remediate this issue, users should upgrade to version 2.274.0-alpha.0 or later.
  hunt_leads:
    - lead: Review CloudTrail logs or AWS Config logs for unexpected Redshift superuser activity or unauthorized GRANT statements.
      technique_id: T1190
      data_needed:
        - AWS CloudTrail
        - Amazon Redshift Audit Logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The statements are reachable through crafted user names, comments, or passwords.
  mitigation_plan:
    - priority: immediate
      action: Audit current database grants for the PUBLIC role to detect unauthorized access.
      owner: SOC
      addresses: CVE-2026-115418
      evidence: review existing table grants to PUBLIC.
---

The @aws-cdk/aws-redshift-alpha module within the AWS Cloud Development Kit (CDK) contains an SQL injection vulnerability in its database-query custom resource handlers. This flaw allows an attacker who can influence construct property values (specifically user names, comments, or passwords) to execute arbitrary SQL statements with Amazon Redshift superuser privileges. This could lead to unauthorized privilege escalation and modification of cluster access controls.

## Impact
Successful exploitation grants an attacker Amazon Redshift superuser privileges, allowing them to grant access to cluster users or modify database permissions, potentially compromising the integrity and confidentiality of data stored within the cluster.

## Recommendation
- Upgrade the @aws-cdk/aws-redshift-alpha module to version 2.274.0-alpha.0 or later immediately.
- Review existing table grants and permissions assigned to the PUBLIC role in impacted Amazon Redshift clusters to identify unauthorized modifications.
