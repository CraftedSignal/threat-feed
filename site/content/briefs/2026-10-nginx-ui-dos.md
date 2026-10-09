---
title: Unauthenticated Denial of Service via Temporary File Exhaustion in Nginx UI
slug: 2026-10-nginx-ui-dos
description: An unauthenticated remote attacker can exploit CVE-2026-107805 in Nginx UI by sending malicious requests that trigger premature staging of large, unsigned request bodies, leading to disk space and I/O exhaustion.
date: "2026-10-09T21:23:53Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:0xjacky:nginx_ui:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - webserver
  - availability
vendors:
  - 0xJacky
products:
  - Nginx UI (2.5.0-2.5.x)
cves:
  - id: CVE-2026-107805
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-j3hg-9rp3-5hw9
  - https://github.com/0xJacky/nginx-ui/commit/8c9b9a1aff218ee6c980d047b750e49da3c46796
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-107805
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Nginx UI to version 2.6.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Source provides 2.6.0 as the remediation version for CVE-2026-107805.
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy request body limits.
      owner: IT Operations
      addresses: CVE-2026-107805
      evidence: Deployment-specific reverse-proxy body limits may reduce practical impact.
---

Nginx UI versions 2.5.0 through 2.5.x are vulnerable to a high-severity denial-of-service condition involving improper request processing. The application's node-signature authentication logic incorrectly stages the body of incoming requests to temporary files on disk before validating the associated cryptographic signature or body digest.

An unauthenticated remote attacker capable of reaching the Nginx UI API can initiate requests containing syntactically correct signature metadata but arbitrary, large body payloads. Because the application processes these requests and commits them to temporary storage prior to authentication, a stream of concurrent, malicious requests can consume system-level disk capacity, saturate I/O throughput, and exhaust request-processing threads. This behavior disrupts the availability of Nginx UI and may impact other services residing on the same infrastructure. The vulnerability is strictly an availability concern and does not facilitate unauthorized access, data confidentiality loss, or integrity compromise.

## Impact

The vulnerability allows for resource exhaustion, leading to a denial of service. The impact is primarily on system availability, where excessive concurrent requests can lead to full temporary partitions or I/O starvation. The degree of impact depends heavily on environmental factors such as available disk quotas, configured reverse-proxy body limits, and server-side concurrency constraints.

## Recommendation

Prioritize upgrading to Nginx UI 2.6.0 or later to mitigate the vulnerability. The patch introduces a check to authenticate request metadata prior to staging and implements improved request body streaming with size constraints and automatic cleanup for discarded requests.

* Upgrade Nginx UI to 2.6.0 or later immediately.
* Review temporary filesystem usage patterns to detect spikes in `/tmp` or designated staging directories associated with Nginx UI.
* Implement application-level request size limits in front-end reverse proxies (e.g., standard Nginx or HAProxy) to prevent oversized payloads from reaching the application API.
* Configure system-level disk quotas for the service account running Nginx UI to contain the impact of storage exhaustion.
