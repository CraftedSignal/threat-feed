---
title: Unauthenticated Information Disclosure in LearnDash LMS
slug: 2026-09-learndash-api-exposure
description: LearnDash LMS versions prior to 4.10.3 are vulnerable to unauthenticated REST API access (CVE-2024-1208, CVE-2024-1210), allowing unauthorized remote actors to exfiltrate quiz and examination content.
date: "2026-09-03T08:51:15Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:learndash:learndash_lms:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:learndash:learndash:*:*:*:*:*:wordpress:*:*
tags:
  - vulnerability
  - web-application
  - wordpress
vendors:
  - LearnDash
products:
  - LearnDash LMS (< 4.10.3)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592.002
    technique_name: Software
    evidence: Unauthenticated API access exposes LearnDash quizzes and questions to all visitors.
    confidence_band: high
cves:
  - id: CVE-2024-1208
    cvss: 5.3
    epss: 0.05285
  - id: CVE-2024-1210
    cvss: 5.3
    epss: 0.02027
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KARLEMILNIKKA-CVE-2024-1208-AND-CVE-2024-1210
rules:
  - title: Detect Unauthenticated Access to LearnDash Quiz API
    description: Detects unauthorized access to LearnDash LMS REST API endpoints which are vulnerable to CVE-2024-1208 and CVE-2024-1210
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LearnDash LMS to version 4.10.3
      owner: IT Operations
      due: 48h
      evidence: Plugin patch for CVE-2024-1208 and CVE-2024-1210
  mitigation_plan:
    - priority: immediate
      action: Disable LearnDash REST API using the learndash_rest_api_enabled filter if the functionality is unused
      owner: IT Operations
      addresses: CVE-2024-1208 and CVE-2024-1210
      evidence: Recommended remediation via class-ld-rest-api.php documentation
---

LearnDash LMS, a widely used WordPress learning management system, contains critical vulnerabilities (CVE-2024-1208 and CVE-2024-1210) within its REST API implementation. These vulnerabilities permit unauthenticated remote attackers to access sensitive quiz content and examination questions via the `/ldlms/v1/` and `/ldlms/v2/` REST API endpoints. Because the plugin fails to enforce proper authorization checks on these API routes, any visitor can retrieve private assessment data without being enrolled in the associated courses or possessing administrative privileges. This vulnerability exposes proprietary course content and compromises the integrity of assessments that rely on these questions to verify student knowledge. The vulnerability was disclosed and fixed in version 4.10.3 of the LearnDash plugin. Organizations utilizing LearnDash are at risk of data exfiltration and intellectual property theft if they have not patched to the current secure version.

## Impact

Successful exploitation results in the unauthorized disclosure of proprietary educational content, including complete sets of quiz and exam questions. This facilitates cheating and undermines the educational integrity of the platform. There are no reports of widespread active exploitation, but the public availability of proof-of-concept exploits significantly increases the likelihood of opportunistic discovery by malicious actors targeting WordPress-based environments.

## Recommendation

Prioritized actions for security and IT teams:

- Update the LearnDash LMS plugin to version 4.10.3 or later immediately to resolve CVE-2024-1208 and CVE-2024-1210.
- Audit WordPress access logs for anomalous requests to the `/wp-json/ldlms/v1/` or `/wp-json/ldlms/v2/` endpoints, specifically monitoring for high-frequency requests from non-authenticated source IPs.
- Evaluate the necessity of exposing the LearnDash REST API and, if not required for business functionality, utilize the `learndash_rest_api_enabled` filter in `class-ld-rest-api.php` to disable the API for sensitive post types.
