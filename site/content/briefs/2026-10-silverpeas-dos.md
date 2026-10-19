---
title: Denial of Service Vulnerability in Silverpeas
slug: 2026-10-silverpeas-dos
description: CVE-2024-42849 is a remote denial-of-service vulnerability in Silverpeas 6.4.2 and lower, where an attacker can exhaust server resources by submitting an excessively large password string during a password change request.
date: "2026-10-19T19:22:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:silverpeas:silverpeas:*:*:*:*:*:*:*:*
vendors:
  - Silverpeas
products:
  - Silverpeas (<= 6.4.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An issue in Silverpeas v.6.4.2 and lower allows a remote attacker to cause a denial of service via the password change function.
    confidence_band: high
cves:
  - id: CVE-2024-42849
    cvss: 6.5
    epss: 0.0122
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NJMBB8-CVE-2024-42849
rules:
  - title: Detect Excessive Request Lengths to Password Change Endpoints
    description: Detects potential exploitation of CVE-2024-42849 by identifying unusually large HTTP requests sent to the password change endpoint.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit Silverpeas instances for version 6.4.2 or lower
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-42849 impacts versions 6.4.2 and lower.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to limit request size to the password change endpoint
      owner: IT Operations
      addresses: CVE-2024-42849
      evidence: Exploit relies on submitting a 1MB payload to exhaust hashing resources.
---

CVE-2024-42849 is a security vulnerability in Silverpeas version 6.4.2 and lower that allows a remote, authenticated attacker to trigger a denial-of-service (DoS) condition. The vulnerability resides within the application's password change functionality. By crafting a request that includes an excessively large string (approximately 1MB) as the new password, an attacker forces the application to perform resource-intensive hashing operations. These operations exhaust system CPU and memory resources, rendering the Silverpeas application unresponsive to legitimate user traffic. A proof-of-concept exploit for this vulnerability has been publicly released, increasing the risk of exploitation for organizations running unpatched versions of the platform.

## Attack Chain

1. The attacker performs successful authentication to the Silverpeas web application.
2. The attacker navigates to the user profile or password management interface to initiate a password change request.
3. The attacker intercepts the HTTP POST request intended for the password change endpoint using a proxy tool such as Burp Suite.
4. The attacker modifies the password parameters in the intercepted request, substituting the standard password with a 1MB string.
5. The attacker forwards the modified HTTP request to the Silverpeas server.
6. The Silverpeas server receives the request and attempts to process the password change, invoking its internal hashing algorithm on the 1MB payload.
7. The system encounters extreme resource exhaustion as it attempts to hash the oversized string, leading to high CPU and memory utilization.
8. The application service crashes or becomes unresponsive to all other users, resulting in a denial of service.

## Impact

Successful exploitation results in a complete denial of service for the Silverpeas application, preventing legitimate users from accessing or utilizing the platform. Given the availability of a public PoC, there is a moderate risk to any organization operating Silverpeas 6.4.2 or earlier, particularly in enterprise environments where service availability is critical.

## Recommendation

1. Upgrade Silverpeas to a version post-6.4.2 immediately to mitigate the underlying resource handling flaw.
2. Implement request size limits on the web server or application gateway level to reject incoming HTTP requests containing abnormally large payloads for password fields.
3. Monitor web server logs for HTTP POST requests with unusually large request bodies or request lengths targeting password change endpoints.
