---
title: Credential Exposure in Splunk Connect for Kafka via HEC Configuration
slug: 2026-08-splunk-kafka-hec
description: Splunk Connect for Kafka versions below 2.2.7 are vulnerable to credential theft through an unauthenticated REST API endpoint, allowing attackers to redirect HEC traffic to malicious servers.
date: "2026-08-19T22:45:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-exposure
  - api-vulnerability
  - splunk
vendors:
  - Splunk
products:
  - Splunk Connect for Kafka (< 2.2.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user who can reach the Kafka Connect Representational State Transfer (REST) API could configure a non-secure Hypertext Transfer Protocol (HTTP) Event Collector endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-76402
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76402
  - https://help.splunk.com/en/data-management/integrate-data-with-add-ons/splunk-connect-for-kafka/2.2/install/install-splunk-connect-for-kafka
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Splunk Connect for Kafka to version 2.2.7
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76402 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Kafka Connect REST API via firewall rules
      owner: IT Operations
      addresses: CVE-2026-76402
      evidence: Source notes unauthenticated users can reach the API
---

Splunk Connect for Kafka versions below 2.2.7 contain a vulnerability (CVE-2026-76402) that permits an unauthenticated user with network access to the Kafka Connect REST API to perform unauthorized configuration changes. The flaw stems from insufficient validation of HTTP Event Collector (HEC) endpoints, specifically the lack of mandatory secure transport (HTTPS) for these connections. By reconfiguring the HEC endpoint to an attacker-controlled server, the connector can be coerced into transmitting sensitive authentication credentials and data streams to an external, unauthorized host. This exposure compromises the confidentiality of data passing through the connector and allows for the modification of event delivery paths. Defenders should prioritize updating affected Splunk Connect for Kafka deployments to version 2.2.7 or later to enforce secure HEC configuration.

## Impact

Successful exploitation leads to the exposure of HEC authentication credentials and the interception or manipulation of sensitive data streams within the Kafka to Splunk ingestion pipeline. This results in significant risks to data integrity and unauthorized access to downstream Splunk Enterprise environments.

## Recommendation

* Upgrade Splunk Connect for Kafka to version 2.2.7 or higher immediately to address CVE-2026-76402.
* Audit existing Kafka Connect REST API configurations for non-standard or unauthorized HEC endpoint URLs that utilize HTTP instead of HTTPS.
* Restrict network access to the Kafka Connect REST API to authorized management IP addresses only, preventing unauthenticated reachability from the broader network.
