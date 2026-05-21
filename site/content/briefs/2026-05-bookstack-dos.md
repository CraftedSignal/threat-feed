---
title: BookStack 25.12.1 Denial-of-Service Vulnerability
slug: 2026-05-bookstack-dos
description: A denial-of-service vulnerability exists in BookStack version 25.12.1, and a public exploit (EDB-52571) is available, increasing the risk to unpatched systems.
date: "2026-05-21T13:31:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - webapps
  - exploit
products:
  - BookStack (25.12.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.exploit-db.com/exploits/52571
rules:
  - title: Detect BookStack Denial-of-Service Exploit Attempt via URI
    description: Detects potential attempts to exploit the BookStack denial-of-service vulnerability by monitoring for suspicious URI patterns.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect BookStack Denial-of-Service Exploit Attempt via User Agent
    description: Detects potential attempts to exploit the BookStack denial-of-service vulnerability by monitoring for suspicious User Agent strings.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

A denial-of-service vulnerability has been identified in BookStack version 25.12.1. A public exploit, EDB-52571, has been published on Exploit-DB, making exploitation easier. The availability of this exploit increases the risk to unpatched systems, as attackers can leverage it to disrupt the availability of BookStack instances. This vulnerability allows an attacker to potentially overload the system, rendering it unresponsive to legitimate users.

## Attack Chain

1.  Attacker identifies a vulnerable BookStack 25.12.1 instance.
2.  Attacker crafts a malicious HTTP request designed to exploit the denial-of-service vulnerability.
3.  Attacker sends the crafted HTTP request to the target BookStack server.
4.  The BookStack server processes the malicious request, consuming excessive resources.
5.  The server's resource consumption (CPU, memory, I/O) spikes, leading to performance degradation.
6.  Legitimate user requests are delayed or dropped due to resource exhaustion.
7.  The BookStack instance becomes unresponsive, resulting in a denial-of-service condition.
8.  Administrators may need to restart the BookStack service to restore functionality.

## Impact

Successful exploitation of this denial-of-service vulnerability can lead to significant disruption of BookStack services. Affected organizations may experience downtime, preventing users from accessing critical documentation and knowledge base resources. The number of affected users will depend on the size of the BookStack deployment, but any unpatched instance is vulnerable. The impact is service unavailability and potential data integrity issues due to abnormal termination.

## Recommendation

-   Upgrade BookStack to a patched version that addresses the denial-of-service vulnerability to prevent exploitation (reference: BookStack 25.12.1 is vulnerable).
-   Monitor web server logs for suspicious HTTP requests that may indicate exploitation attempts (reference: webserver log source in Sigma rules below).
-   Implement rate limiting and request filtering on the web server hosting BookStack to mitigate potential denial-of-service attacks (reference: webserver log source in Sigma rules below).
