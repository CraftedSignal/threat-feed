---
title: IBM WebSphere Liberty Identity Spoofing Vulnerability (CVE-2026-3621)
slug: 2026-04-websphere-spoofing
description: IBM WebSphere Application Server Liberty versions 17.0.0.3 through 26.0.0.4 are susceptible to identity spoofing when applications are deployed without proper authentication and authorization configurations, potentially leading to unauthorized access and privilege escalation.
date: "2026-04-23T00:18:31Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cve-2026-3621
  - websphere
  - identity spoofing
  - cwe-269
vendors:
  - IBM
products:
  - WebSphere Application Server - Liberty
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-3621
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3621
  - https://www.ibm.com/support/pages/node/7270437
rules:
  - title: Detect WebSphere Liberty Unauthorized Access Attempt
    description: Detects attempts to access WebSphere Liberty applications without proper authentication headers, potentially indicating identity spoofing attempts related to CVE-2026-3621.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
  - title: WebSphere Liberty Unprotected Resource Access
    description: Detects access to sensitive resources on WebSphere Liberty without prior authentication, potentially indicating an attempt to exploit CVE-2026-3621.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3621 identifies an identity spoofing vulnerability affecting IBM WebSphere Application Server Liberty versions 17.0.0.3 through 26.0.0.4. This vulnerability arises when applications are deployed on WebSphere Liberty without authentication or authorization mechanisms configured. An attacker could potentially exploit this flaw to impersonate legitimate users or services, gaining unauthorized access to resources and performing actions on their behalf. This vulnerability was reported to IBM and assigned a CVSS v3.1 base score of 7.5, indicating a high potential impact. Successful exploitation allows for unauthorized actions and data access within the vulnerable WebSphere Liberty environment.

## Attack Chain

1.  An attacker identifies a WebSphere Liberty instance running a vulnerable version (17.0.0.3 - 26.0.0.4).
2.  The attacker determines that an application is deployed on the WebSphere Liberty instance without proper authentication or authorization configurations.
3.  The attacker crafts a malicious request, spoofing the identity of a legitimate user. This might involve manipulating HTTP headers or other request parameters.
4.  The malicious request is sent to the vulnerable application on the WebSphere Liberty server.
5.  The WebSphere Liberty server, lacking proper authentication checks, processes the request under the forged identity.
6.  The attacker gains unauthorized access to resources or performs actions associated with the spoofed identity.
7.  The attacker can potentially escalate privileges by accessing administrative functions or sensitive data accessible to the spoofed user.

## Impact

Successful exploitation of CVE-2026-3621 can lead to significant consequences. An attacker could gain unauthorized access to sensitive data, modify application configurations, or perform actions on behalf of legitimate users, potentially leading to data breaches, service disruption, or complete system compromise. The vulnerability is particularly concerning for organizations that rely on WebSphere Liberty for critical applications and have not implemented proper authentication and authorization controls. The number of affected organizations is currently unknown but will depend on the prevalence of vulnerable WebSphere Liberty instances deployed without adequate security measures.

## Recommendation

*   Apply appropriate authentication and authorization configurations to all applications deployed on IBM WebSphere Application Server Liberty to mitigate CVE-2026-3621, as described in [IBM's advisory](https://www.ibm.com/support/pages/node/7270437).
*   Deploy the Sigma rule "Detect WebSphere Liberty Unauthorized Access Attempt" to identify suspicious requests lacking authentication headers.
*   Upgrade to a non-vulnerable version of IBM WebSphere Application Server Liberty outside the range of 17.0.0.3 through 26.0.0.4.
