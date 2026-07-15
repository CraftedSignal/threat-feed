---
title: Unauthenticated Information Disclosure in GPUStack
slug: 2026-07-gpustack-info-disclosure
description: An unauthenticated information disclosure vulnerability, CVE-2026-58658, in GPUStack through version 2.2.1 allows attackers to access sensitive inference logs containing prompts and completions and modify worker configurations by exploiting unprotected /serveLogs and /debug endpoints.
date: "2026-07-15T18:22:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - web-application
vendors:
  - GPUStack
products:
  - GPUStack <= 2.2.1
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: attackers can enumerate model instance IDs to stream serving logs containing prompts and completions, change log levels, and read memory profiling data without any authentication.
    confidence_band: high
cves:
  - id: CVE-2026-58658
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58658
rules:
  - title: Detects CVE-2026-58658 Exploitation - Unauthenticated Access to GPUStack Endpoints
    description: Detects exploitation of CVE-2026-58658 by identifying unauthenticated HTTP GET/POST requests to the `/serveLogs` or `/debug` endpoints of GPUStack, indicating attempts to access sensitive inference logs or modify worker configuration.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-58658 details an unauthenticated information disclosure vulnerability in GPUStack versions up to and including 2.2.1, which was addressed in commit 4e20551. This vulnerability allows remote, unauthenticated attackers to gain unauthorized access to sensitive operational data and configuration settings. By exploiting unprotected `/serveLogs` and `/debug` endpoints on the worker port, attackers can enumerate model instance IDs to stream highly sensitive inference logs containing proprietary prompts and completions. Furthermore, they can alter log levels and read memory profiling data, potentially leading to disruption of service or leakage of confidential information. This flaw presents a significant risk to organizations using GPUStack for machine learning inference, as it could expose intellectual property and operational details.

## Attack Chain

1. Attacker identifies a vulnerable GPUStack instance (version 2.2.1 or earlier) with its worker port exposed.
2. Attacker sends an unauthenticated HTTP GET request to the `/serveLogs` endpoint on the worker port to enumerate available model instance IDs.
3. Using the identified model instance IDs, the attacker sends further unauthenticated HTTP GET requests to `/serveLogs` to stream sensitive inference logs, which contain prompts and completions.
4. Concurrently, the attacker sends unauthenticated HTTP GET requests to the `/debug` endpoint to read memory profiling data, potentially uncovering system architectural details.
5. The attacker leverages the `/debug` endpoint with unauthenticated HTTP POST/PUT requests to modify worker configuration settings, such as altering log levels, which could impact operational integrity or aid further reconnaissance.
6. The attacker successfully exfiltrates sensitive inference data and potentially disrupts or reconfigures the GPUStack worker.

## Impact

Successful exploitation of CVE-2026-58658 results in unauthorized access to highly sensitive information, including machine learning model prompts and completions, which can reveal proprietary business logic, intellectual property, or confidential user data. Attackers can also read memory profiling data, potentially gaining insights into the application's internal workings and infrastructure. Furthermore, the ability to modify worker configurations via the `/debug` endpoint could lead to denial of service, service degradation, or facilitate further malicious activities on the compromised system. The CVSS v3.1 Base Score of 8.2 indicates a high severity threat, with potential for significant data loss and operational disruption.

## Recommendation

* Patch CVE-2026-58658 by upgrading GPUStack to a version beyond 2.2.1 (fixed in commit 4e20551) immediately.
* Deploy the Sigma rule provided in this brief to your SIEM to detect unauthenticated access attempts to the `/serveLogs` and `/debug` endpoints.
* Enable comprehensive web server logging for all GPUStack instances to capture detailed HTTP request information, including URI stems, methods, and status codes.
