---
brief_id: brief-2026-10-20-aiohttp-file-descriptor-exhaustion
event_id: brief-2026-10-20-aiohttp-file-descriptor-exhaustion
revision: 1
activity_at: "2026-10-20T23:55:48Z"
title: 'AIOHTTP: File descriptor exhaustion via multipart requests (CVE-2026-111066)'
slug: 2026-10-aiohttp-file-descriptor-exhaustion
description: An unauthenticated remote attacker can trigger a denial-of-service condition by sending specially crafted multipart requests that cause uncontrolled file descriptor allocation in the aiohttp library.
date: "2026-10-20T23:55:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:aio-libs:aiohttp:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - webserver
  - vulnerability
vendors:
  - aio-libs
products:
  - aiohttp (>= 2.0.0, < 3.14.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can exhaust file descriptors with specially crafted multipart requests.
    confidence_band: high
cves:
  - id: CVE-2026-111066
    epss: 0.00381
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-9xw5-w5jj-pvcg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111066
  - https://github.com/aio-libs/aiohttp/releases/tag/v3.14.4
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch aiohttp to version 3.14.4 across all production environments
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111066 remediation
  hunt_leads:
    - lead: Identify systems running aiohttp versions < 3.14.4
      technique_id: T1499
      data_needed:
        - Software Bill of Materials (SBOM) or package dependency scans
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerable versions identified in GHSA-9xw5-w5jj-pvcg
  mitigation_plan:
    - priority: immediate
      action: Upgrade aiohttp to 3.14.4
      owner: IT Operations
      addresses: CVE-2026-111066
      evidence: Vendor patch release
---

The aiohttp library (versions 2.0.0 through 3.14.3) is susceptible to a resource exhaustion vulnerability (CVE-2026-111066) due to improper management of file descriptors during the processing of multipart requests. An unauthenticated attacker can exploit this by submitting specifically crafted multipart HTTP requests to an application that utilizes the Request.post() method. 

When processed, the library fails to properly throttle or limit the number of file descriptors created on behalf of the request, allowing an attacker to exhaust the operating system's file descriptor limits. This leads to a denial-of-service (DoS) condition where the affected application becomes unresponsive or unable to handle new network connections or file operations. Defenders should prioritize updating to aiohttp 3.14.4 or later to implement the necessary resource constraints.

## Attack Chain

1. The attacker identifies an internet-facing application that uses the aiohttp library for handling HTTP multipart/form-data uploads.
2. The attacker crafts a malicious HTTP POST request containing an excessive number of multipart parts or specific header values designed to trigger the vulnerable code path in Request.post().
3. The target application receives the malicious request and initiates the parsing process within the aiohttp multipart handler.
4. The library allocates file descriptors for each part of the multipart request without enforcing per-request limits.
5. The attacker sustains the transmission of these requests to rapidly increase the count of open file descriptors associated with the application process.
6. The application process reaches the operating system's configured maximum file descriptor limit (ulimit).
7. The application service crashes or becomes unresponsive to legitimate users, resulting in a successful denial-of-service.

## Impact

Successful exploitation results in the unavailability of the web service. This vulnerability impacts any system utilizing aiohttp 2.0.0 through 3.14.3 to process multipart requests, potentially affecting a wide array of web services, internal APIs, and microservices. Because the attack requires no authentication and low complexity, it presents a significant risk for service disruption in environments exposed to untrusted network traffic.

## Recommendation

- Upgrade the aiohttp package to version 3.14.4 or later immediately.
- Monitor web server error logs for persistent "too many open files" or "OSError: [Errno 24] Too many open files" messages, which may indicate active exploitation or resource exhaustion.
- Review network edge configurations to implement rate limiting on POST requests directed at multipart/form-data endpoints.
- Use system-level telemetry to monitor file descriptor usage per application process, specifically for services using the affected aiohttp versions.
