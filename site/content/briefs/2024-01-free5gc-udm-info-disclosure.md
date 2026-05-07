---
title: Free5GC UDM Information Disclosure via Malformed Request
slug: 2024-01-free5gc-udm-info-disclosure
description: The free5GC UDM component fails to validate the `supi` path parameter in six GET handlers, allowing an unauthenticated attacker to inject control characters and trigger a `500 Internal Server Error` that exposes internal infrastructure details.
date: "2026-05-07T02:09:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - input-validation
  - free5GC
vendors:
  - free5gc
products:
  - udm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27642
    cvss: 7.5
    epss: 0.00099
references:
  - https://github.com/advisories/GHSA-585v-hcgf-jhfr
rules:
  - title: Detect UDM 500 Error with URL Parsing Failure
    description: Detects HTTP 500 errors from the UDM service that contain a URL parsing error, indicating a possible information disclosure attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect UDM 400 Error with invalid Supi
    description: Detects HTTP 400 errors from the UDM service that reports an invalid Supi.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The free5GC UDM (Unified Data Management) component, specifically versions up to and including v1.4.2, is vulnerable to an information disclosure vulnerability. The vulnerability lies in the `nudm-sdm` service, where six GET handlers lack proper validation of the `supi` path parameter. This omission allows an unauthenticated attacker to inject control characters into the `supi` parameter. Consequently, the UDM forwards a malformed request to UDR (Unified Data Repository), leading to a `500 Internal Server Error`. This error response inadvertently exposes internal infrastructure details, including the UDR hostname and port, full internal API path structure, UDR API version, and internal service naming conventions. This vulnerability is a missed fix of CVE-2026-27642.

## Attack Chain

1.  The attacker sends a GET request to a vulnerable UDM endpoint (`/nudm-sdm/v2/:supi/smf-select-data`, `/nudm-sdm/v2/:supi/nssai`, `/nudm-sdm/v2/:supi/trace-data`, `/nudm-sdm/v2/:supi/sm-data`, `/nudm-sdm/v2/:supi`, or `/nudm-sdm/v2/:supi/ue-context-in-smf-data`).
2.  The `supi` parameter in the URL contains injected control characters (e.g., `%00`).
3.  The UDM fails to validate the `supi` parameter using `validator.IsValidSupi()`.
4.  The UDM constructs a URL to the UDR, incorporating the malformed `supi`.
5.  Go's `net/url` parser rejects the malformed URL containing control characters.
6.  The UDM catches the parsing error.
7.  The UDM responds with a `500 SYSTEM_FAILURE` error, including internal details in the `detail` field.
8.  The attacker receives the `500` response containing sensitive internal information.

## Impact

An unauthenticated remote attacker can obtain internal infrastructure details by sending a crafted GET request to a vulnerable UDM endpoint. This information includes the internal UDR hostname and port, the full internal API path structure, the UDR API version, and the internal service naming convention. This information can then be used to facilitate further attacks against the UDR or other internal 5G core components.

## Recommendation

*   Apply the fix recommended by the vendor to include `validator.IsValidSupi()` to all six affected handlers in `internal/sbi/api_subscriberdatamanagement.go` following the pattern already used in `HandleGetAmData`.
*   Monitor web server logs for HTTP 500 responses from UDM endpoints containing "net/url: invalid control character in URL" in the response body (see example in content).
*   Deploy the Sigma rule detecting HTTP 500 responses with the string `net/url: invalid control character in URL` in the response body.
