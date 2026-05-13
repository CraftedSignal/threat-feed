---
title: Langflow Vulnerability Allows Denial of Service
slug: 2026-05-langflow-dos
description: An authenticated remote attacker can exploit a vulnerability in Langflow to perform a denial-of-service attack, impacting system availability.
date: "2026-05-13T07:49:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - langflow
  - web-application
products:
  - Langflow
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1284
rules:
  - title: Detect Langflow DoS - Abnormal HTTP Request Rate
    description: Detects a potential Denial of Service attack against Langflow based on an abnormally high rate of HTTP requests from a single source IP address.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
---

A vulnerability in Langflow allows an authenticated, remote attacker to conduct a denial-of-service (DoS) attack. While specific details of the vulnerability are not provided, the impact involves a loss of system availability. Defenders should prioritize identifying and mitigating potential vectors for authenticated users to trigger resource exhaustion or service disruption within Langflow. Since the advisory lacks specific technical details about the vulnerability, proactive monitoring and anomaly detection of Langflow's resource consumption are crucial.

## Attack Chain

1. The attacker authenticates to the Langflow application.
2. The attacker crafts a malicious request or input designed to trigger the vulnerability.
3. The malicious request is sent to a vulnerable endpoint within Langflow.
4. The Langflow application processes the malicious request.
5. Due to the vulnerability, Langflow experiences excessive resource consumption (CPU, memory, or network).
6. Langflow becomes unresponsive or crashes, denying service to legitimate users.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the Langflow application unavailable to legitimate users. The lack of availability can disrupt workflows and processes that rely on Langflow. The number of affected users depends on the deployment size and user base of the Langflow instance.

## Recommendation

*   Monitor Langflow's resource consumption (CPU, memory, network) for unusual spikes that could indicate a DoS attack.
*   Inspect Langflow's logs for suspicious activity or error messages related to resource exhaustion.
*   Deploy the Sigma rule detecting abnormal HTTP request patterns targeting Langflow to identify potential DoS attempts.
