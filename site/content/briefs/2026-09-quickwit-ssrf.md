---
title: SSRF Vulnerability in Quickwit SQS File Source
slug: 2026-09-quickwit-ssrf
description: Quickwit versions through 0.9.0 contain a Server-Side Request Forgery vulnerability allowing unauthenticated attackers to perform internal network scanning and service fingerprinting via the create-source API.
date: "2026-09-16T19:52:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quickwit:quickwit:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - web-application
vendors:
  - Quickwit
products:
  - Quickwit (<= 0.9.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Attackers can supply a malicious queue_url to the create-source API to scan internal networks and fingerprint services based on connection response differences.
    confidence_band: high
cves:
  - id: CVE-2026-92719
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92719
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Quickwit to version > 0.9.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92719
  hunt_leads:
    - lead: Detect requests to create-source API with suspicious queue_url values
      technique_id: T1046
      data_needed:
        - Web server access logs for create-source API endpoints
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The issue resides in the handling of the queue_url parameter within SQS file sources.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access for Quickwit service nodes via firewalls
      owner: IT Operations
      addresses: CVE-2026-92719
      evidence: The application allows unauthenticated attackers to force the node to issue requests to arbitrary internal addresses
---

Quickwit versions through 0.9.0 are affected by a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-92719. The issue resides in the handling of the queue_url parameter within SQS file sources. The application fails to properly validate the host and scheme components of this parameter when processing requests via the create-source API. This flaw allows an unauthenticated attacker to force the Quickwit node to perform outbound requests to arbitrary internal IP addresses or domains. By analyzing the differential responses from the node, attackers can map internal infrastructure, perform port scanning, and fingerprint internal services that are not directly accessible from the internet. This vulnerability is particularly critical for deployments where the Quickwit instance resides within an internal network segment with access to sensitive management interfaces or other microservices.

## Impact

The successful exploitation of CVE-2026-92719 enables unauthorized network reconnaissance within the host environment. By leveraging the Quickwit node as a proxy, attackers can bypass network access controls to interact with internal services. This leads to the exposure of internal service versions, identification of reachable assets, and potential precursor activity for further exploitation of internal-only APIs.

## Recommendation

1. Upgrade all instances of Quickwit to a version beyond 0.9.0 immediately to apply the patch for CVE-2026-92719.
2. Implement strict network egress filtering on all Quickwit nodes to limit connections to known-good SQS service endpoints.
3. Monitor webserver access logs for anomalous requests to the create-source API containing non-standard or internal URL schemes (e.g., file://, gopher://) or local IP ranges within the queue_url parameter.
4. Ensure that the service account running the Quickwit process follows the principle of least privilege, restricting its ability to communicate with internal network segments.
