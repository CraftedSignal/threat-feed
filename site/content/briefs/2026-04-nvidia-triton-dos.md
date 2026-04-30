---
title: NVIDIA Triton Inference Server Denial-of-Service Vulnerability (CVE-2026-24146)
slug: 2026-04-nvidia-triton-dos
description: NVIDIA Triton Inference Server is vulnerable to denial of service due to insufficient input validation that, when combined with a large number of outputs, can cause a server crash.
date: "2026-04-07T18:16:39Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-24146
  - denial-of-service
  - nvidia
  - triton
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-24146
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24146
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5816
  - https://www.cve.org/CVERecord?id=CVE-2026-24146
rules:
  - title: Detect Suspicious Triton Inference Server Requests
    description: Detects requests to the NVIDIA Triton Inference Server that may be attempting to exploit CVE-2026-24146 by sending a large number of outputs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Triton Server Crashes in Syslog
    description: Detects potential crashes of the NVIDIA Triton Inference Server by monitoring syslog for out-of-memory errors.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - system
      - linux
rules_count: 2
---

NVIDIA Triton Inference Server is susceptible to a denial-of-service (DoS) vulnerability identified as CVE-2026-24146. This flaw stems from insufficient input validation within the server software. An attacker can exploit this by sending specially crafted requests with a large number of expected outputs to the server. If successful, this causes excessive memory allocation leading to a server crash, rendering the service unavailable to legitimate users. This vulnerability impacts any organization utilizing affected versions of the NVIDIA Triton Inference Server. Publicly available information regarding affected versions is limited, but it is critical that organizations monitor for updates and apply necessary patches promptly.

## Attack Chain

1. An attacker identifies a vulnerable NVIDIA Triton Inference Server instance.
2. The attacker crafts a malicious request designed to trigger excessive output generation.
3. The crafted request is sent to the Triton Inference Server via HTTP or gRPC.
4. The server receives the request and attempts to process it.
5. Due to insufficient input validation, the server allocates an excessive amount of memory.
6. Repeated requests exhaust available memory resources.
7. The server crashes due to an out-of-memory condition.
8. Legitimate users are unable to access the inference server, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2026-24146 leads to a denial-of-service condition on the NVIDIA Triton Inference Server. This can disrupt AI inference workloads, potentially impacting critical applications that rely on these services. The impact is significant for organizations that depend on the availability of their AI models for real-time decision-making or other operational needs. The specific number of affected organizations is unknown, but any organization using a vulnerable version of the Triton Inference Server is at risk.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of NVIDIA Triton Inference Server as soon as it is available from NVIDIA to remediate CVE-2026-24146.
*   Implement input validation on the server-side to prevent malicious requests with excessive output parameters; this is a general mitigation strategy since specific filters are unavailable.
*   Deploy the Sigma rule `Detect Suspicious Triton Inference Server Requests` to identify potential exploitation attempts targeting the vulnerability.
*   Monitor web server logs (category `webserver`, product `linux`) for unusual request patterns that may indicate exploitation attempts, focusing on cs-uri-query parameters related to output size or count.
