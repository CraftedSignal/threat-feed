---
title: Local File Disclosure and Denial of Service in Stoatchat January Service
slug: 2026-09-stoatchat-svg-rfi
description: An unauthenticated remote attacker can exploit an improper SVG resolution vulnerability in the Stoatchat January media proxy to perform local file enumeration, arbitrary file disclosure, and memory exhaustion via unbounded filesystem I/O.
date: "2026-09-26T19:00:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:stoatchat:stoatchat:*:*:*:*:*:*:*:*
tags:
  - file-disclosure
  - denial-of-service
  - web-application
  - cve-2026-100676
vendors:
  - stoatchat
products:
  - January (< 0.15.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker who causes the service to proxy an attacker-hosted SVG (e.g. via the /proxy endpoint) can determine whether local files exist
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: can determine whether local files exist through observable response-time differences
    confidence_band: high
cves:
  - id: CVE-2026-100676
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100676
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Stoatchat January service to version 0.15.5
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in 0.15.5.
  mitigation_plan:
    - priority: immediate
      action: Implement rate limiting on /proxy endpoint
      owner: IT Operations
      addresses: CVE-2026-100676
      evidence: A single request can also generate an unbounded amount of local filesystem I/O
---

The January media proxy and embed service within the Stoatchat platform (versions prior to 0.15.5) contains a critical vulnerability regarding how it handles SVG files containing external references. When the service is instructed to proxy an attacker-controlled SVG file via the /proxy endpoint, it fails to sanitize or validate &lt;image href> tags. Instead, it attempts to resolve these paths against the local filesystem.

An unauthenticated remote attacker can exploit this behavior in three ways: by using timing side-channels to determine the existence of local files, by forcing the re-encoding of local image files to disclose their contents, and by generating massive, unbounded filesystem I/O and memory usage. This resource-intensive exploitation can exhaust system memory and disk throughput, leading to a denial-of-service condition. Research indicates a single request can trigger over 4 GB of file reads. This flaw is patched in version 0.15.5.

## Attack Chain

1. Attacker hosts a malicious SVG file on an external server containing a crafted &lt;image href> tag targeting a local system path.
2. Attacker sends a GET/POST request to the target's /proxy endpoint, providing the URL of the malicious SVG file.
3. The January service fetches the SVG file and parses the contents.
4. The service encounters the &lt;image href> tag and attempts to resolve the provided path on the local filesystem.
5. Attacker observes response times (timing side-channel) to confirm the existence of specific files on the server.
6. Service reads the targeted local files into memory, performing re-encoding operations.
7. Attacker requests the proxied output, receiving the disclosed local image content.
8. Concurrent requests lead to excessive I/O and memory pressure, triggering a service crash or system-wide denial-of-service.

## Impact

Successful exploitation leads to the unauthorized disclosure of local image files and denial-of-service. The vulnerability allows an unauthenticated attacker to probe the filesystem structure and extract local image data. Furthermore, the lack of resource constraints allows a single attacker to cause significant system instability through memory exhaustion, potentially impacting all services hosted on the same infrastructure.

## Recommendation

1. Upgrade the Stoatchat January media proxy service to version 0.15.5 or later immediately.
2. Implement strict egress filtering on the January service host to prevent it from reaching arbitrary external URLs for image proxying if not required by business logic.
3. Monitor webserver logs for excessive requests to the /proxy endpoint, especially those referencing internal or system-like directory paths, to identify exploitation attempts.
4. Deploy network-based rate limiting on the /proxy endpoint to mitigate potential denial-of-service attempts.
