---
title: free5GC NEF Denial-of-Service via Unreachable notifyUri
slug: 2024-01-02-free5gc-nef-dos
description: free5GC's NEF component is vulnerable to a denial-of-service attack where an attacker can create a PFD subscription with an attacker-controlled `notifyUri`, and when a PFD change is triggered, NEF attempts to deliver a notification to the specified URI, and if the URI is unreachable, NEF terminates the entire process, causing a service outage, and this can be triggered without authentication in version 4.2.1, making it easily exploitable.
date: "2024-01-02T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - vulnerability
  - free5gc
vendors:
  - free5gc
products:
  - nef
  - free5gc
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-rxrq-fv76-26pr
  - https://github.com/free5gc/free5gc/issues/924
  - https://github.com/free5gc/nef/pull/25
  - https://github.com/free5gc/free5gc/issues/858
  - https://github.com/free5gc/free5gc/issues/859
  - https://github.com/free5gc/free5gc/issues/862
iocs:
  - type: url
    value: http://127.0.0.1:1/notify
ioc_counts:
  url: 1
rules:
  - title: Detect NEF PFD Subscription with Unreachable notifyUri
    description: Detects PFD subscription creation with a notifyUri pointing to a likely unreachable IP address and port
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect NEF PFD Management Transactions
    description: Detects POST requests to the /3gpp-pfd-management/v1/afdos/transactions endpoint, potentially indicating an attempt to trigger the PFD change vulnerability.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

free5GC's Network Exposure Function (NEF) is susceptible to a denial-of-service vulnerability. An attacker with the ability to create a PFD subscription can specify an arbitrary `notifyUri`. When a PFD change event occurs, the NEF attempts to send an HTTP POST request to the configured `notifyUri`. If this notification delivery fails (e.g., due to connection refused, DNS resolution failure, or timeout), the NEF process terminates due to an unhandled error condition. This behavior, present in version 4.2.1, allows an unauthenticated attacker to remotely trigger a complete NEF service outage. The vulnerability is triggered by posting to `/3gpp-traffic-influence/v1/afdos/subscriptions`, `/nnef-pfdmanagement/v1/subscriptions`, and `/3gpp-pfd-management/v1/afdos/transactions`, reachable without authentication due to misconfiguration of SBI route groups.

## Attack Chain

1.  The attacker sends an HTTP POST request to `/3gpp-traffic-influence/v1/afdos/subscriptions` to create an AF context with `afAppId` set to "app-nef-dos" and `anyUeInd` to true.
2.  The NEF creates a new AF context subscription and returns a `201 Created` response with the `Location` header indicating the new subscription URI.
3.  The attacker sends an HTTP POST request to `/nnef-pfdmanagement/v1/subscriptions` to create a PFD subscription, including a malicious `notifyUri` such as `http://127.0.0.1:1/notify`.
4.  The NEF stores the PFD subscription with the attacker-controlled `notifyUri`.
5.  The attacker sends an HTTP POST request to `/3gpp-pfd-management/v1/afdos/transactions` to trigger a PFD change.
6.  The NEF processes the PFD change request and returns a `201 Created` response.
7.  The NEF attempts to deliver an asynchronous notification to the attacker-specified `notifyUri` via an HTTP POST request.
8.  Because the `notifyUri` is unreachable (e.g., port 1 is closed), the outbound HTTP POST fails, triggering the `logger.Fatal(err)` call and terminating the NEF process with exit code 1.

## Impact

The vulnerability leads to a complete denial-of-service condition for the free5GC NEF. Successful exploitation results in the NEF process terminating abruptly, causing loss of service and requiring a restart. Since the trigger chain is unauthenticated in v4.2.1, any attacker capable of reaching the NEF's SBI interface can remotely trigger the process termination. This can be repeated to sustain the outage indefinitely, severely impacting the availability of the 5G network services reliant on the NEF. The vulnerability affects free5GC v4.2.1.

## Recommendation

*   Apply the upstream fix available at [https://github.com/free5gc/nef/pull/25](https://github.com/free5gc/nef/pull/25) to prevent the `logger.Fatal` call on notification delivery failure.
*   Deploy the Sigma rule "Detect NEF PFD Subscription with Unreachable notifyUri" to detect attempts to create subscriptions with suspicious callback URLs.
*   Monitor NEF container logs for `[FATA][NEF][PFDMng]` messages, which indicate that the NEF process has terminated due to the vulnerability, as shown in the container log example.
*   Review and harden the authentication configuration for NEF SBI route groups to prevent unauthenticated access, as discussed in [free5gc/free5gc#858](https://github.com/free5gc/free5gc/issues/858), [free5gc/free5gc#859](https://github.com/free5gc/free5gc/issues/859), and [free5gc/free5gc#862](https://github.com/free5gc/free5gc/issues/862).
*   Audit all code paths that use `logger.Fatal` and replace them with recoverable error handling.
