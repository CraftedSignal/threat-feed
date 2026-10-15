---
title: Unbounded HTTP Response Header Buffering in react/http
slug: 2026-10-react-http-dos
description: The react/http library is vulnerable to a memory exhaustion Denial of Service (DoS) due to the lack of size constraints on incoming HTTP response headers (CVE-2026-104827).
date: "2026-10-15T22:27:19Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:reactphp:http:*:*:*:*:*:*:*:*
vendors:
  - ReactPHP
products:
  - react/http (1.0.0-1.11.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can exploit this by streaming an infinite header section without the required terminator, causing the client-side process to continuously allocate memory.
    confidence_band: high
cves:
  - id: CVE-2026-104827
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-g4f2-2pf3-2pwj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104827
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade react/http to a patched version beyond 1.11.0
      owner: IT Operations
      due: 72h
      evidence: Source advisory recommends upgrading
  mitigation_plan:
    - priority: immediate
      action: Upgrade react/http to 1.11.1 or later
      owner: Application Security
      addresses: CVE-2026-104827
      evidence: GitHub Advisory GHSA-g4f2-2pf3-2pwj
---

The react/http library, specifically within the `ClientRequestStream` component, fails to impose a size limit on incoming HTTP response headers. The `handleData()` method appends every incoming byte directly to an internal buffer without checking length, searching only for the `\r\n\r\n` or `\n\n` header terminator. An attacker hosting a malicious HTTP endpoint can stream an arbitrary amount of data to a client using the library, withholding the terminator and causing the client's memory consumption to grow monotonically until the PHP `memory_limit` is reached. This results in the crashing of the process or the entire event loop. The vulnerability affects all versions of `react/http` from 1.0.0 through 1.11.0. This issue is remotely exploitable without authentication, including cases where a client is directed to a malicious URL via an HTTP redirect, making it a significant risk for applications that perform arbitrary external requests.

## Impact

The vulnerability allows for a remotely triggerable, unauthenticated denial of service against any application that uses the `react/http` `Browser` class to fetch data from untrusted sources. Successful exploitation causes the application process to crash due to memory exhaustion, leading to a loss of service availability for the affected process or worker. No confidentiality or integrity impact occurs, but the service disruption is total for the victim process.

## Recommendation

* Upgrade the `react/http` package to a version beyond 1.11.0 that implements the necessary header size constraints.
* Audit applications utilizing `react/http` to identify endpoints that perform outbound requests to potentially untrusted or attacker-controlled domains.
* Implement egress filtering or network-level timeouts for outbound requests to mitigate the impact of long-lived, slow-header-streaming connections.
* Deploy the patches for CVE-2026-104827 across all environments where `react/http` is used as a client-side component.
