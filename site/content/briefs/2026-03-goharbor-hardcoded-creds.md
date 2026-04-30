---
title: GoHarbor Harbor v2.15.0 and Below Vulnerable to Hardcoded Credentials
slug: 2026-03-goharbor-hardcoded-creds
description: GoHarbor Harbor version 2.15.0 and below is vulnerable to the use of hard-coded credentials, allowing an attacker to use the default password and gain unauthorized access to the web UI.
date: "2026-03-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - hardcoded-credentials
  - goharbor
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4404
  - https://cwe.mitre.org/data/definitions/1393.html
  - https://github.com/goharbor/harbor/issues/1937
  - https://github.com/goharbor/harbor/pull/22751
  - https://goharbor.io/docs/1.10/install-config/run-installer-script/#:~:text=If%20you%20did%20not%20change%20them%20in%20harbor.yml,%20the%20default%20administrator%20username%20and%20password%20are%20admin%20and%20Harbor12345
  - https://www.kb.cert.org/vuls/id/577436
rules:
  - title: Detect GoHarbor Login with Default Credentials
    description: Detects login attempts to GoHarbor web UI using the default username 'admin' and password 'Harbor12345'.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1110
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GoHarbor Login Form Request
    description: Detects requests to the GoHarbor login form, which can be used to identify potential brute-force or credential stuffing attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GoHarbor Harbor, a popular open-source cloud native registry, is susceptible to a critical vulnerability (CVE-2026-4404) in versions 2.15.0 and below. This flaw stems from the use of hardcoded credentials, specifically a default password, which, if unchanged, allows unauthorized access to the web UI. An attacker exploiting this vulnerability can bypass authentication and potentially gain full control over the Harbor instance. This poses a significant risk to organizations using affected Harbor versions, as it can lead to data breaches, container image tampering, and other malicious activities. The vulnerability was reported in March 2026, and defenders should prioritize upgrading or mitigating affected instances.

## Attack Chain

1.  Attacker identifies a GoHarbor Harbor instance running version 2.15.0 or below.
2.  Attacker accesses the web UI login page of the Harbor instance.
3.  Attacker enters the default username ("admin") and password ("Harbor12345"), as documented in the official GoHarbor documentation.
4.  The Harbor instance authenticates the attacker due to the use of default credentials.
5.  Attacker gains access to the Harbor web UI with administrator privileges.
6.  Attacker can now manage container images, repositories, and users within the Harbor instance.
7.  Attacker may pull sensitive images, inject malicious code into existing images, or create new malicious images.
8.  The attacker uses the now compromised Harbor instance to distribute malicious container images throughout the organization's infrastructure, leading to widespread compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over a GoHarbor Harbor instance. This can lead to the compromise of container images, potentially injecting malware into the software supply chain. The impact could range from data exfiltration and service disruption to full system compromise, depending on the privileges associated with the Harbor instance. Given the widespread use of GoHarbor in cloud-native environments, this vulnerability presents a significant risk to numerous organizations.

## Recommendation

*   Immediately upgrade GoHarbor Harbor instances to a version greater than 2.15.0 to remediate CVE-2026-4404.
*   If upgrading is not immediately feasible, change the default "admin" password ("Harbor12345") to a strong, unique password as outlined in the GoHarbor documentation.
*   Deploy the provided Sigma rule to detect login attempts using the default credentials against the Harbor web UI based on webserver logs.
*   Regularly review and update credentials for all services and applications to prevent the exploitation of default or hardcoded passwords.
