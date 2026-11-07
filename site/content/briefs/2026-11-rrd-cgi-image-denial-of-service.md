---
brief_id: brief-2026-11-07-rrd-cgi-image-denial-of-service
event_id: brief-2026-11-07-rrd-cgi-image-denial-of-service
revision: 1
activity_at: "2026-11-07T20:20:47Z"
title: 'RRD::CGI::Image: Denial of service via tzset() (CVE-2026-123776)'
slug: 2026-11-rrd-cgi-image-denial-of-service
description: RRD::CGI::Image versions through 0.01 pass unsanitized CGI query parameters to the tzset() function, allowing an attacker to trigger a process hang via a FIFO or device path.
date: "2026-11-07T20:20:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation for web log regex patterns.
products:
  - RRD::CGI::Image (through 0.01)
cves:
  - id: CVE-2026-123776
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/575
  - https://metacpan.org/dist/RRD-CGI-Image
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify CGI requests where the tz parameter value contains file paths or device identifiers
      data_needed:
        - Web server logs (uri-query or GET parameters)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: An attacker can provide a FIFO or device path as the parameter value, which causes the CGI process to block.
  mitigation_plan:
    - priority: medium
      action: Implement input validation to restrict the tz parameter to standard timezone names and reject paths
      owner: IT Operations
      addresses: CVE-2026-123776
      evidence: RRD::CGI::Image versions through 0.01 pass CGI query parameters containing tz to tzset()
  gaps:
    - Lack of vendor-provided patch or updated version in the source notification
---

RRD::CGI::Image versions through 0.01 are vulnerable to a denial-of-service condition where the tz parameter in a CGI query is passed directly to the Perl tzset() function. By supplying a FIFO or device path as the value for this parameter, an attacker can cause the underlying CGI process to block indefinitely, impacting application availability.

## Impact

An attacker can induce a denial-of-service by blocking the CGI process, which may lead to resource exhaustion if multiple requests are sent to the affected Perl-based web application.

## Recommendation

- Audit web server access logs for requests to RRD::CGI::Image endpoints containing unusual 'tz' parameter values such as '/dev/' or pipe-like paths.
- Patch or upgrade the RRD::CGI::Image module if a secure version becomes available via CPAN.
- Implement request validation on the web server or application firewall level to restrict the 'tz' parameter to expected time zone format strings.
