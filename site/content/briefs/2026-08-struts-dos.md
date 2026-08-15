---
title: Denial of Service Vulnerability in Apache Struts JSON Plugin (CVE-2026-73633)
slug: 2026-08-struts-dos
description: A public proof-of-concept exploit for CVE-2026-73633 allows unauthenticated attackers to perform denial-of-service attacks by forcing excessive CPU and memory consumption via the Apache Struts JSON plugin.
date: "2026-08-15T09:26:32Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Apache
products:
  - Struts 2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This causes consumption (and CPU usage). ... It only caused strain on the container's resources.
    confidence_band: high
cves:
  - id: CVE-2026-73633
    cvss: 7.5
references:
  - https://sploitus.com/exploit?id=ABF46B8C-CDA0-50DF-8402-76B81B3EC03F
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Configure WAF to enforce strict content-length and request-body size limits for all incoming JSON POST requests.
      owner: IT Operations
      due: 24h
      evidence: The parser reads the entire json content of the request body into memory at once.
  hunt_leads:
    - lead: Identify applications running Apache Struts and review web server logs for abnormally large POST requests to JSON endpoints.
      technique_id: T1499
      data_needed:
        - webserver logs (request size, URI, timestamp)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This fixed value is proportional to the filling size parameter.
---

CVE-2026-73633, also tracked as S2-072, is a denial-of-service (DoS) vulnerability impacting the Apache Struts 2 JSON plugin. The vulnerability arises from the plugin's JSON filling function, which automatically parses and converts incoming JSON request bodies. When processing large or deeply nested JSON arrays, the parser reads the entire request body into memory simultaneously, leading to significant CPU spikes and sustained memory consumption.

The vulnerability is exploitable by an unauthenticated attacker sending a specially crafted JSON payload to an endpoint utilizing the vulnerable plugin. Proof-of-concept code has been published publicly, demonstrating that resource strain is proportional to the size of the injected JSON array. While the PoC observed did not trigger an immediate service crash, the sustained resource depletion can cause service degradation or secondary failures due to resource exhaustion in resource-constrained environments like containers. Defenders should prioritize patching or implementing request size limits on Struts-based applications.

## Impact

Successful exploitation leads to high CPU utilization and sustained memory exhaustion on the host server or container. While the vulnerability is not reported to cause arbitrary code execution, the impact on availability is significant for production environments, potentially rendering the service unresponsive to legitimate traffic.

## Recommendation

- Implement request body size limits at the WAF or reverse proxy level to mitigate the impact of abnormally large JSON payloads.
- Review Apache Struts configurations to ensure the JSON plugin is restricted to only necessary endpoints.
- Monitor webserver metrics for anomalous spikes in CPU usage or memory growth correlated with incoming POST requests.
- Patch affected instances of Apache Struts once vendor updates are available.
