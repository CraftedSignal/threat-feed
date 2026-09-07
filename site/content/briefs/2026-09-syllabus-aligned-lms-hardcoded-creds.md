---
title: Hard-Coded Credentials in SourceCodester Syllabus-Aligned Learning Management & Examination System
slug: 2026-09-syllabus-aligned-lms-hardcoded-creds
description: SourceCodester Syllabus-Aligned Learning Management & Examination System 1.0 contains a vulnerability in db.php that allows remote attackers to gain unauthorized access via hard-coded credentials.
date: "2026-09-07T06:51:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:sourcecodester:syllabus-aligned_learning_management_&_examination_system:1.0:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Syllabus-Aligned Learning Management & Examination System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The issue affects some unknown processing of the file db.php. Executing a manipulation can lead to hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-86276
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86276
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to affected LMS instances at the perimeter firewall
      owner: SOC
      due: 24h
      evidence: Source notes the attack can be executed remotely and exploits are published.
  mitigation_plan:
    - priority: immediate
      action: Audit db.php for hard-coded credentials and implement secure configuration management
      owner: IT Operations
      addresses: CVE-2026-86276
      evidence: The vulnerability is caused by hard-coded credentials in db.php.
---

A critical vulnerability exists in version 1.0 of the SourceCodester Syllabus-Aligned Learning Management & Examination System. The issue resides within the 'db.php' file, which contains hard-coded credentials that can be exploited by remote, unauthenticated attackers to gain unauthorized access to the system. Since the credentials are embedded directly within the source code of the database configuration file, any instance of this software exposed to the internet is inherently vulnerable. Attackers with knowledge of the default codebase can gain administrative or database-level access without needing to perform traditional brute-force or credential-harvesting activities. Proof-of-concept exploit code has been published publicly, increasing the risk of active exploitation by opportunistic actors. Organizations currently running this specific version of the Learning Management System (LMS) should immediately restrict network access or audit the configuration to rotate compromised credentials.

## Impact

Successful exploitation allows remote, unauthenticated attackers to gain unauthorized access to the application, potentially leading to full database compromise, sensitive data exfiltration, and administrative control over the learning environment. This vulnerability affects all deployments of version 1.0 of the Syllabus-Aligned Learning Management & Examination System.

## Recommendation

Prioritize auditing all instances of the SourceCodester Syllabus-Aligned Learning Management & Examination System. Immediately rotate any credentials found within 'db.php' and ensure that the application is not exposed to the public internet. If the system cannot be immediately updated or secured, restrict network access to the application using a web application firewall or VPN.
