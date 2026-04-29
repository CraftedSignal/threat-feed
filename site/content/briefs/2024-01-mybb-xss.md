---
title: MyBB Recent Threads 17.0 Persistent Cross-Site Scripting Vulnerability (CVE-2018-25309)
slug: 2024-01-mybb-xss
description: MyBB Recent threads 17.0 contains a persistent cross-site scripting vulnerability (CVE-2018-25309) that allows attackers to inject malicious scripts by creating threads with crafted subject lines, leading to arbitrary JavaScript execution in the browsers of users viewing the index page.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - xss
  - cve-2018-25309
  - web-application
vendors:
  - MyBB
products:
  - Recent threads 17.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25309
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25309
  - https://www.vulncheck.com/advisories/mybb-recent-threads-persistent-cross-site-scripting
rules:
  - title: Detect MyBB XSS via Thread Title
    description: Detects potential cross-site scripting (XSS) attempts in MyBB forums by looking for script tags in the subject parameter when creating a new thread.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MyBB XSS in Thread Creation Form
    description: Detects XSS attempts by identifying script tags within the 'subject' field of a POST request to the 'newthread.php' page in MyBB.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MyBB Recent Threads 17.0 is vulnerable to a persistent cross-site scripting (XSS) vulnerability, identified as CVE-2018-25309. This vulnerability allows attackers to inject malicious JavaScript code into the subject lines of forum threads. When other users view the index page or any page displaying the affected thread titles, the injected script executes within their browsers. This can lead to session hijacking, defacement, or other malicious actions. The vulnerability was reported in 2018 but remains relevant for older MyBB installations that have not been patched or upgraded. The attacker exploits a lack of proper input sanitization in the thread creation process.

## Attack Chain

1.  Attacker crafts a malicious thread subject containing JavaScript code (e.g., `<script>alert("XSS")</script>`).
2.  Attacker submits the crafted thread subject when creating a new thread on the MyBB forum.
3.  The MyBB application stores the malicious subject in the database without proper sanitization.
4.  A user visits the forum's index page or any page that displays the thread's subject.
5.  The MyBB application retrieves the thread subject from the database and injects it into the HTML of the page.
6.  The user's browser parses the HTML and executes the injected JavaScript code.
7.  The attacker's JavaScript code performs malicious actions, such as stealing cookies or redirecting the user to a malicious website.

## Impact

Successful exploitation of this XSS vulnerability can lead to various impacts, including session hijacking, where an attacker steals a user's session cookie and gains unauthorized access to their account. Website defacement is also possible, where the attacker alters the appearance of the forum. In a targeted attack, the attacker could potentially gain control over the MyBB server itself, depending on the permissions of the user whose session is hijacked and the server configuration. Given the popularity of MyBB, a successful exploit could affect numerous forums and their users.

## Recommendation

*   Deploy the Sigma rule `Detect MyBB XSS via Thread Title` to identify potential exploitation attempts by detecting script tags in HTTP request parameters to thread creation endpoints.
*   Inspect web server logs for HTTP requests containing `<script>` tags in the `subject` parameter when creating a new thread, as this is indicative of a potential XSS attack (see references for vulnerable parameter).
*   Upgrade MyBB installations to a patched version that includes proper input sanitization to prevent XSS vulnerabilities.
