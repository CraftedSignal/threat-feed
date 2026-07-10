---
title: free5GC UDR Memory Leak Vulnerability Leads to Denial of Service
slug: 2024-01-24-free5gc-udr-dos
description: An unauthenticated attacker can exploit a memory leak in free5GC UDR versions prior to 1.4.3 by sending repeated HTTP requests to the OAM endpoint, causing uncontrolled memory growth and denial of service.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - free5GC
  - UDR
  - CVE-2026-41135
  - memory-leak
  - denial-of-service
  - 5G
vendors:
  - free5GC
products:
  - free5GC UDR
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-41135
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41135
rules:
  - title: Detect High Request Rate to free5GC UDR OAM Endpoint
    description: Detects abnormally high request rates to the free5GC UDR OAM endpoint, potentially indicating a DoS attack exploiting CVE-2026-41135.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Specific User Agent Sending Requests to free5GC UDR OAM Endpoint
    description: This rule detects a specific User-Agent identified as being used during exploitation of free5GC vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The free5GC UDR (User Data Repository) is a critical component of 5G mobile core networks, functioning as the Policy Control Function (PCF). A memory leak vulnerability, identified as CVE-2026-41135, affects free5GC UDR versions prior to 1.4.3. This vulnerability allows any unauthenticated attacker with network access to the PCF's SBI (Service Based Interface) to trigger uncontrolled memory growth. This is achieved by sending repeated HTTP requests to the OAM (Operations, Administration, and Management) endpoint. The root cause lies in the repeated registration of CORS middleware within an HTTP handler, leading to a continuous expansion of the Gin router's handler chain. This progressive memory exhaustion ultimately results in a Denial of Service (DoS) condition, preventing User Equipments (UEs) from obtaining necessary AM (Access and Mobility) and SM (Session Management) policies, effectively blocking 5G session establishment. The vulnerability was patched in version 1.4.3.

## Attack Chain

1.  Attacker gains network access to the free5GC UDR's PCF SBI interface.
2.  Attacker crafts and sends repeated HTTP requests to the UDR's OAM endpoint.
3.  The HTTP handler processes the request.
4.  The `router.Use()` call inside the handler registers a new CORS middleware.
5.  With each request, the Gin router's handler chain grows due to the repeated middleware registration.
6.  Memory consumption progressively increases due to the expanding handler chain.
7.  The UDR server experiences memory exhaustion.
8.  The UDR becomes unresponsive, resulting in a Denial of Service (DoS) condition, preventing UEs from obtaining AM and SM policies and blocking 5G session establishment.

## Impact

The successful exploitation of CVE-2026-41135 leads to a Denial of Service (DoS) condition affecting the free5GC UDR. This prevents User Equipments (UEs) from obtaining necessary AM and SM policies, effectively blocking 5G session establishment. Depending on the scale of the deployment, this could impact hundreds or thousands of users within the affected network segment. Service providers relying on vulnerable versions of free5GC UDR face potential service outages and disruptions.

## Recommendation

*   Upgrade free5GC UDR to version 1.4.3 or later to remediate CVE-2026-41135.
*   Deploy the Sigma rules in this brief to your SIEM to detect potential exploitation attempts targeting the UDR OAM endpoint (see rules below).
*   Monitor webserver logs for abnormally high request rates to the UDR OAM endpoint to identify potential attackers.
