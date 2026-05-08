---
title: free5GC PCF Nil Pointer Dereference Vulnerability
slug: 2024-01-29-free5gc-pcf-panic
description: A nil-pointer dereference vulnerability exists in free5GC's PCF when handling POST requests to `/npcf-smpolicycontrol/v1/sm-policies`. When a downstream UDR lookup returns a 404 error, the handler continues execution instead of returning, leading to a nil response struct dereference and a panic. This results in an HTTP 500 error for the request, but the PCF process continues running. The vulnerability is triggered by sending a POST request with input that causes the downstream UDR lookup to fail, such as an unknown DNN. This issue affects free5GC versions v4.1.0 and v4.2.1.
date: "2024-01-29T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - web-application
vendors:
  - free5GC
products:
  - PCF
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-wr8j-6chw-gm6p
  - https://github.com/free5gc/free5gc/issues/803
  - https://github.com/free5gc/pcf/pull/62
  - https://github.com/free5gc/free5gc/issues/844
iocs:
  - type: url
    value: http://10.100.200.9:8000/npcf-smpolicycontrol/v1/sm-policies
  - type: url
    value: http://smf.free5gc.org:8000/npcf-smpolicycontrol/v1/notify
ioc_counts:
  url: 2
rules:
  - title: Detect free5GC PCF HTTP 500 Errors
    description: Detects free5GC PCF returning HTTP 500 errors, potentially indicating a nil pointer dereference vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect free5GC PCF Invalid DNN in POST Request
    description: Detects free5GC PCF POST requests with a DNN value likely to cause a UDR lookup failure.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A nil-pointer dereference vulnerability has been identified in free5GC's Policy Control Function (PCF) when processing POST requests to the `/npcf-smpolicycontrol/v1/sm-policies` endpoint. This occurs when a downstream User Data Repository (UDR) lookup fails and returns a 404 error. Instead of properly handling the error, the PCF handler continues execution, leading to a nil response struct being dereferenced, which results in a panic. The Gin framework's recovery mechanism converts the panic into an HTTP 500 error. This vulnerability can be triggered by sending a single POST request with crafted input, such as an unknown DNN, that causes the downstream UDR lookup to fail. The issue has been validated against free5GC version v4.1.0 and confirmed to be present in v4.2.1.

## Attack Chain

1.  Attacker sends an HTTP POST request to `/npcf-smpolicycontrol/v1/sm-policies` on the PCF endpoint.
2.  The POST request includes a JSON payload with parameters such as `supi`, `pduSessionId`, `dnn`, `sliceInfo`, `servingNetwork`, `accessType`, and `notificationUri`.
3.  The `dnn` parameter in the JSON payload is set to a value that is unknown to the UDR (e.g., "internet-bad").
4.  The PCF attempts to perform a UDR lookup based on the provided `dnn` value.
5.  The UDR lookup fails, returning a 404 Not Found error to the PCF.
6.  The PCF handler logs the OpenAPI error but does not properly handle the error condition by returning.
7.  The handler attempts to dereference a nil response struct, resulting in a nil pointer dereference and a panic.
8.  The Gin recovery middleware catches the panic and returns an HTTP 500 Internal Server Error to the attacker.

## Impact

The vulnerability results in a denial-of-service condition where any POST request that leads to a 404 error from the UDR lookup will trigger a panic in the PCF, resulting in an HTTP 500 error for the specific request. The PCF process itself remains running due to the Gin recovery middleware, but the endpoint becomes temporarily unavailable for the attacker's specific request. The vulnerability affects free5GC v4.1.0 and v4.2.1. An unauthenticated attacker can exploit the issue due to a separate authorization gap in the PCF route group.

## Recommendation

*   Apply the patch from the upstream fix ([https://github.com/free5gc/pcf/pull/62](https://github.com/free5gc/pcf/pull/62)) to resolve the nil pointer dereference vulnerability.
*   Implement the Sigma rule "Detect free5GC PCF HTTP 500 Errors" to monitor for HTTP 500 responses from the PCF endpoint, which may indicate exploitation attempts.
*   Monitor PCF container logs for the error message `panic: runtime error: invalid memory address or nil pointer dereference` to identify instances where the vulnerability has been triggered.
*   Address the authorization gap in the PCF `Npcf_SMPolicyControl` route group as described in free5gc/free5gc#844 to prevent unauthenticated exploitation of the vulnerability.
