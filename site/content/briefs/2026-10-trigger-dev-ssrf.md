---
title: Trigger.dev SSRF via Unvalidated Webhook Delivery URLs
slug: 2026-10-trigger-dev-ssrf
description: An authenticated user can configure malicious webhook endpoints in Trigger.dev (< 4.5.2) to perform server-side request forgery (SSRF) against internal services and cloud metadata endpoints.
date: "2026-10-02T20:22:51Z"
lastmod: "2026-10-02T20:23:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - insecure-design
  - cloud-security
vendors:
  - Trigger.dev
products:
  - trigger.dev (< 4.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An authenticated user can configure webhook alert channels to target internal network addresses and cloud metadata endpoints.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The dashboard replay action authorizes the source run, but the target environment for the replayed run is taken verbatim from the request body and is never checked for org or project membership.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qxpp-qjg8-x4jv
rules:
  - title: Detect Cross-Tenant Replay Attempt in Trigger.dev
    description: Detects HTTP POST requests to the replay endpoint where the environment parameter is manually specified, potentially indicating an attempt to target an unauthorized tenant.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade trigger.dev to 4.5.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies 4.5.2 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access from the Trigger.dev server to internal IP ranges via firewall or egress proxy.
      owner: IT Operations
      addresses: SSRF primitive targeting internal network
      evidence: Source identifies lack of private-IP/loopback blocking as the root cause.
updates:
  - at: "2026-10-02T20:23:02Z"
    level: L2
    summary: 'added detection rule: Detect Cross-Tenant Replay Attempt in Trigger.dev'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-qxpp-qjg8-x4jv
---

Trigger.dev versions prior to 4.5.2 contain a critical server-side request forgery (SSRF) vulnerability. The application allows authenticated organization members to configure webhook alert channels with arbitrary delivery URLs. These URLs are stored as unvalidated strings and are subsequently fetched by the Trigger.dev control plane to deliver alerts using POST requests. 

The application lacks any validation mechanism - such as host blocklists for private IP ranges, loopback addresses (127.0.0.1), or link-local addresses (e.g., 169.254.169.254) - at the time of creation or during the alert delivery process. An attacker with low-privilege organization access can supply an internal-only URL, causing the server to proxy signed POST requests to internal services or cloud IMDS endpoints. Because the requests include valid HMAC signatures computed by the platform, they may bypass internal authentication logic that relies on these signatures, resulting in potential unauthorized command execution or data exfiltration from internal APIs.

## Attack Chain

1. Attacker authenticates to a Trigger.dev instance using a valid user account.
2. Attacker invokes the project API endpoint `/api/v1/projects/<projectRef>/alertChannels`.
3. Attacker submits a POST request containing a malicious `channelData` payload where the `url` points to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/`).
4. The application saves the malicious URL to the `ProjectAlert` model without validating the hostname or IP range.
5. Attacker triggers a task run failure event within their controlled environment.
6. The `deliverAlert` service fetches the stored webhook URL, triggering a server-side request to the target internal IP.
7. The target internal service receives the signed POST request, potentially treating it as a legitimate system-originated event.

## Impact

Successful exploitation allows an attacker to interact with services reachable from the Trigger.dev control plane, including internal management APIs, cloud instance metadata services (IMDS), and other local network resources. This can result in credential theft, internal data exposure, or the unauthorized manipulation of internal service configurations that rely on the HMAC headers provided by the Trigger.dev platform.

## Recommendation

* Upgrade Trigger.dev to version 4.5.2 or later immediately to incorporate input validation for webhook URLs.
* Implement an egress filtering or proxy layer on the network hosting the Trigger.dev control plane to block outbound traffic to private (RFC 1918), loopback, and link-local address spaces.
* Audit application logs for suspicious webhook alert channel creation events targeting non-public IP addresses.
