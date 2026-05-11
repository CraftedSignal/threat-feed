---
title: '@vitejs/plugin-rsc Denial-of-Service Vulnerability in React Server Components'
slug: 2026-05-vitejs-rsc-dos
description: '@vitejs/plugin-rsc is vulnerable to a denial-of-service attack due to an embedded vulnerable version of react-server-dom-webpack, potentially causing resource exhaustion.'
date: "2026-05-11T14:51:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - react
  - vite
vendors:
  - vitejs
  - Facebook
products:
  - '@vitejs/plugin-rsc'
  - react-server-dom-webpack
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
cves:
  - id: CVE-2026-23870
    cvss: 7.5
    epss: 0.00322
references:
  - https://github.com/advisories/GHSA-w94c-4vhp-22gx
  - https://github.com/facebook/react/security/advisories/GHSA-rv78-f8rc-xrxh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23870
rules:
  - title: Detect CVE-2026-23870 Exploitation Attempt - High Resource Consumption
    description: Detects CVE-2026-23870 exploitation attempt — monitors web server logs for suspicious patterns indicative of resource exhaustion attacks against @vitejs/plugin-rsc
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-23870 Exploitation Attempt - Repeated Requests
    description: Detects CVE-2026-23870 exploitation attempt — alerts on repeated requests to specific endpoints, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

The `@vitejs/plugin-rsc` package, used for React Server Components, is vulnerable to a denial-of-service (DoS) attack. This vulnerability stems from the fact that `@vitejs/plugin-rsc` vendors `react-server-dom-webpack`, a component that had a known vulnerability in versions prior to 19.2.6. Attackers could exploit this by sending crafted requests that consume excessive server resources, leading to service disruption or unavailability. The affected versions of `@vitejs/plugin-rsc` are those equal to or below 0.5.25. Upgrading to version 0.5.26 or later resolves this issue, incorporating the patched version of `react-server-dom-webpack`. This vulnerability poses a risk to applications using React Server Components with the vulnerable plugin, emphasizing the need for immediate patching. The related CVE ID is CVE-2026-23870.

## Attack Chain

1. An attacker identifies a server running a vulnerable version of `@vitejs/plugin-rsc`.
2. The attacker crafts a malicious HTTP request designed to trigger excessive resource consumption in the React Server Components rendering process.
3. The request is sent to a server endpoint handled by the vulnerable `@vitejs/plugin-rsc` plugin.
4. Upon receiving the request, the server attempts to process the React Server Component, leading to uncontrolled resource allocation via the vulnerable `react-server-dom-webpack` dependency.
5. The server's memory or CPU resources are exhausted due to the unbounded resource allocation.
6. Legitimate users are unable to access the server due to resource starvation.
7. The server becomes unresponsive or crashes, resulting in a denial-of-service condition.
8. Continuous malicious requests maintain the DoS state, preventing recovery without intervention.

## Impact

Successful exploitation of this vulnerability can lead to complete denial of service, rendering affected applications unavailable to users. While the exact number of potential victims is unknown, any application relying on `@vitejs/plugin-rsc` versions 0.5.25 or earlier is at risk. This can impact various sectors and organizations utilizing React Server Components, resulting in business disruption, reputational damage, and potential financial losses due to downtime. The high CVSS score of 7.5 reflects the severity of the potential impact on availability.

## Recommendation

*   Upgrade to `@vitejs/plugin-rsc@0.5.26` or later to patch the vulnerability and mitigate the risk of denial-of-service attacks as mentioned in the advisory (https://github.com/advisories/GHSA-w94c-4vhp-22gx).
*   Deploy a web application firewall (WAF) with rules to detect and block malicious requests targeting the vulnerable endpoint to provide an additional layer of protection while patching is in progress.
*   Monitor web server logs for unusual activity, such as a sudden spike in resource consumption or a high volume of requests to specific endpoints, to detect potential exploitation attempts.
*   Implement resource limits on the server to prevent a single request from exhausting all available resources, mitigating the impact of a successful denial-of-service attack.
