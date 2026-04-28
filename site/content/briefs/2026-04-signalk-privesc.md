---
title: Signal K Server Unauthenticated Privilege Escalation (CVE-2026-33950)
slug: 2026-04-signalk-privesc
description: An unauthenticated attacker can achieve full administrator access on vulnerable Signal K Servers by injecting an admin role via the /enableSecurity endpoint, allowing modification of sensitive vessel data and server configuration.
date: "2026-04-02T17:16:22Z"
severities:
  - critical
tags:
  - cve-2026-33950
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-33950
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33950
  - https://github.com/SignalK/signalk-server/releases/tag/v2.24.0-beta.4
  - https://github.com/SignalK/signalk-server/security/advisories/GHSA-x8hc-fqv3-7gwf
iocs:
  - type: url
    value: https://github.com/SignalK/signalk-server/releases/tag/v2.24.0-beta.4
  - type: url
    value: https://github.com/SignalK/signalk-server/security/advisories/GHSA-x8hc-fqv3-7gwf
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Unauthorized Access to Signal K /enableSecurity Endpoint
    description: Detects unauthorized POST requests to the /enableSecurity endpoint, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive SignalK Endpoints After Potential PrivEsc
    description: Detects access to sensitive endpoints, such as those modifying vessel data or server configuration, potentially indicating attacker activity following successful privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Signal K Server is a server application used on boats for central hub management. Versions prior to 2.24.0-beta.4 are vulnerable to privilege escalation (CVE-2026-33950). An unauthenticated attacker can gain full Administrator access to the SignalK server by exploiting Admin Role Injection via the `/enableSecurity` endpoint. This vulnerability allows attackers to modify sensitive vessel routing data, alter server configurations, and access restricted endpoints without authentication. The vulnerability was reported on April 2nd, 2026 and patched in version 2.24.0-beta.4. Defenders should prioritize patching vulnerable instances of Signal K Server and monitor for suspicious activity targeting the `/enableSecurity` endpoint.

## Attack Chain

1.  The attacker identifies a vulnerable Signal K Server instance running a version prior to 2.24.0-beta.4.
2.  The attacker sends a crafted HTTP request to the `/enableSecurity` endpoint without providing valid authentication credentials.
3.  The crafted request injects an admin role into the server's authorization mechanism.
4.  The Signal K Server improperly authorizes the attacker, granting them administrator privileges.
5.  The attacker leverages the newly acquired administrator privileges to modify vessel routing data.
6.  The attacker alters server configurations to establish persistence or further compromise the system.
7.  The attacker accesses restricted endpoints to gather sensitive information about the vessel and its operations.
8.  The attacker achieves complete control over the Signal K Server, potentially disrupting navigation and compromising vessel safety.

## Impact

Successful exploitation of CVE-2026-33950 allows an unauthenticated attacker to gain full administrator access to a Signal K Server. This can lead to modification of sensitive vessel routing data, potentially causing navigational hazards. Attackers can also alter server configurations to maintain persistence or further compromise the system. The number of victims and specific sectors targeted are currently unknown, but the vulnerability's ease of exploitation poses a significant risk to maritime operations.

## Recommendation

*   Upgrade all Signal K Server instances to version 2.24.0-beta.4 or later to remediate CVE-2026-33950 (https://github.com/SignalK/signalk-server/releases/tag/v2.24.0-beta.4).
*   Deploy the Sigma rule provided below to detect unauthorized access attempts to the `/enableSecurity` endpoint on Signal K Servers.
*   Monitor web server logs for suspicious POST requests to `/enableSecurity` originating from unexpected IP addresses.
