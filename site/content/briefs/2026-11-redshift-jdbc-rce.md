---
brief_id: brief-2026-11-04-redshift-jdbc-rce
event_id: brief-2026-11-04-redshift-jdbc-rce
revision: 1
activity_at: "2026-11-04T00:46:42Z"
title: 'Amazon Redshift JDBC Driver: Remote code execution via unsafe reflection (CVE-2026-119084)'
slug: 2026-11-redshift-jdbc-rce
description: The Amazon Redshift JDBC Driver before version 2.3.0 is vulnerable to remote code execution due to unsafe class loading and reflection triggered by malicious JDBC connection strings or credential profiles.
date: "2026-11-04T00:46:42Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:amazon:redshift_jdbc_driver:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - jdbc
  - amazon-redshift
  - cve-2026-119084
vendors:
  - Amazon
products:
  - Amazon Redshift JDBC Driver (< 2.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: Unsafe reflection in the connection parameter and credentials profile handling of Amazon Redshift JDBC Driver before 2.3.0 might allow an actor who can influence the JDBC connection URL or the AWS credentials profile to execute arbitrary code in the application context
    confidence_band: high
cves:
  - id: CVE-2026-119084
    cvss: 8.1
    kev_status: "false"
references:
  - https://aws.amazon.com/security/security-bulletins/2026-168-aws/
  - https://github.com/aws/amazon-redshift-jdbc-driver/security/advisories/GHSA-qrph-v96m-w2mv
  - https://github.com/aws/amazon-redshift-jdbc-driver/releases/tag/v2.3.0
  - https://sploitus.com/exploit?id=CVE-2026-119084&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Amazon Redshift JDBC Driver to 2.3.0 or later
      owner: IT Operations
      due: 24h
      evidence: To remediate this issue, users should upgrade to version 2.3.0 or later.
  hunt_leads:
    - lead: Search application logs for unexpected or abnormally long JDBC connection strings containing suspicious class paths or reflection-related parameters
      technique_id: T1059
      data_needed:
        - Application logs
        - JDBC connection configuration source logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An actor who can influence the JDBC connection URL or the AWS credentials profile to execute arbitrary code
  mitigation_plan:
    - priority: immediate
      action: Upgrade Amazon Redshift JDBC Driver to 2.3.0
      owner: IT Operations
      addresses: CVE-2026-119084
      evidence: https://github.com/aws/amazon-redshift-jdbc-driver/releases/tag/v2.3.0
---

Amazon Redshift JDBC Driver versions prior to 2.3.0 are susceptible to an RCE vulnerability (CVE-2026-119084) arising from unsafe reflection in connection parameters and AWS credentials profile handling. An unauthenticated attacker capable of influencing the JDBC connection URL or the AWS credentials configuration can execute arbitrary code within the application process, provided a gadget class is present on the application classpath.

## Impact
Successful exploitation allows for remote code execution in the context of the application using the affected driver, potentially leading to full system compromise or lateral movement within the environment hosting the application.

## Recommendation
- Upgrade the Amazon Redshift JDBC Driver to version 2.3.0 or later immediately.
- Audit application configurations that dynamically construct JDBC connection strings from user-supplied input to identify and sanitize potential injection vectors.
- Review AWS credentials profile configuration access to ensure they are not modifiable by untrusted processes or users.
