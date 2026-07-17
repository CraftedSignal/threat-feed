---
title: Sensitive Information Exposure in LearnPress WordPress Plugin (CVE-2026-13765)
slug: 2026-07-learnpress-info-exposure
description: An unauthenticated sensitive information exposure vulnerability (CVE-2026-13765) in the LearnPress - WordPress LMS Plugin for Create and Sell Online Courses, versions up to 4.4.1, allows attackers to extract quiz answers, options, explanations, and question content, including for paid courses.
date: "2026-07-17T05:19:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - information-exposure
  - web
vendors:
  - ThimPress
products:
  - LearnPress – WordPress LMS Plugin for Create and Sell Online Courses <= 4.4.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The LearnPress – WordPress LMS Plugin for Create and Sell Online Courses plugin for WordPress is vulnerable to Sensitive Information Exposure... This makes it possible for unauthenticated attackers to extract...
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: This makes it possible for unauthenticated attackers to extract the correct-answer markers, full option lists, explanations, and question content for any quiz question on the site — including questions belonging to paid courses the attacker is not enrolled in.
    confidence_band: high
cves:
  - id: CVE-2026-13765
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13765
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/ee3bbf20-43fd-4977-b0ba-b81e7a3810d0?source=cve
rules:
  - title: Detects CVE-2026-13765 Exploitation - LearnPress Information Exposure Attempt
    description: Detects attempts to exploit CVE-2026-13765 by accessing LearnPress quiz answer checking functionalities without proper authorization, leading to sensitive information exposure.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1213
    data_sources:
      - webserver
rules_count: 1
---

A critical sensitive information exposure vulnerability, identified as CVE-2026-13765, exists in the LearnPress - WordPress LMS Plugin for Create and Sell Online Courses, affecting all versions up to and including 4.4.1. This flaw, present in the `check_answer` functionality, allows unauthenticated attackers to bypass authorization controls and extract highly sensitive information. This includes correct answer markers, full option lists, detailed explanations, and the content of any quiz question hosted on the site. The impact extends to questions belonging to paid courses, enabling attackers to obtain valuable educational content without enrollment or payment. The vulnerability stems from missing authorization checks (CWE-862) within the plugin's code, enabling a direct attack against web applications utilizing the plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website running the vulnerable LearnPress plugin.
2. The attacker crafts an HTTP GET or POST request targeting a LearnPress endpoint associated with quiz functionality, specifically invoking the `check_answer` logic.
3. The malicious request includes parameters identifying a specific quiz and question, such as `quiz_id` and `question_id`.
4. Due to a missing authorization check, the LearnPress plugin processes the request without verifying the attacker's authentication or enrollment status for the course.
5. The vulnerable `check_answer` function executes and, instead of merely validating an answer, inadvertently retrieves and exposes sensitive details about the question and its solution.
6. The web server returns an HTTP 200 OK response containing the quiz question's correct answer, the complete list of options, the explanation, and the question content.
7. The attacker parses the response to successfully extract the sensitive educational content, including details from paid courses they are not enrolled in.

## Impact

Successful exploitation of CVE-2026-13765 leads to a significant compromise of intellectual property and the integrity of online educational content. Attackers can obtain full quiz solutions, including correct answers, alternative options, and detailed explanations, for any quiz on the platform. This bypasses paywalls and enrollment requirements for paid courses, effectively devaluing the educational offerings and potentially leading to lost revenue for course creators and organizations. The exposure also allows malicious actors to distribute answers, facilitating cheating, and undermining the academic integrity of institutions relying on the LearnPress plugin.

## Recommendation

* Patch CVE-2026-13765 immediately by updating the LearnPress plugin to version 4.4.2 or higher.
* Deploy the `Detects CVE-2026-13765 Exploitation - LearnPress Information Exposure Attempt` Sigma rule to your SIEM and monitor webserver logs for suspicious access patterns to LearnPress quiz-related endpoints.
* Enable comprehensive web server logging for HTTP requests, including URI stems and query parameters, to facilitate detection and investigation of exploitation attempts.
