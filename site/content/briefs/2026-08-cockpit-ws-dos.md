---
title: Memory Exhaustion Denial of Service in cockpit-ws (CVE-2026-76235)
slug: 2026-08-cockpit-ws-dos
description: A heap-based memory leak in the cockpit-ws service allows unauthenticated remote attackers to trigger a denial of service via malformed Cookie headers.
date: "2026-08-19T14:32:59Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Red Hat
products:
  - cockpit-ws
affected_os:
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A memory leak flaw was found in cockpit-ws... allowing a remote unauthenticated attacker to exhaust memory on the host and cause a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-76235
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76235
  - https://access.redhat.com/security/cve/CVE-2026-76235
  - https://bugzilla.redhat.com/show_bug.cgi?id=2519497
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply security updates for cockpit-ws as provided by Red Hat.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76235 security advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict access to TCP port 9090 via firewall
      owner: IT Operations
      addresses: CVE-2026-76235
      evidence: Unauthenticated attacker vector
---

CVE-2026-76235 describes a memory exhaustion vulnerability (CWE-401) affecting the cockpit-ws component in Red Hat Enterprise Linux. The vulnerability resides in the login page handler, which improperly handles heap memory allocation when processing incoming requests containing a 'CockpitLang' cookie. A remote, unauthenticated attacker can repeatedly send requests with this specific cookie to trigger a memory leak, eventually leading to system resource exhaustion and a denial-of-service condition for the affected host. This issue affects various versions of Red Hat Enterprise Linux including RHEL 7, 8, 9, and 10. The vulnerability is classified with a CVSS 3.1 base score of 7.5.

## Attack Chain

1. Attacker identifies a target running the cockpit-ws service (typically listening on TCP 9090).
2. Attacker initiates an unauthenticated HTTP connection to the Cockpit login endpoint.
3. Attacker crafts an HTTP request header containing the 'CockpitLang' cookie.
4. Attacker sends multiple requests in rapid succession to the login handler.
5. The cockpit-ws service fails to release heap memory associated with the 'CockpitLang' header processing.
6. Memory usage on the host system grows until all available RAM is exhausted.
7. The host experiences a service failure or system-wide denial of service.

## Impact

Successful exploitation results in a denial of service, rendering the Cockpit management interface and potentially other host services unresponsive. This affects systems deployed in production environments utilizing Red Hat Enterprise Linux 7, 8, 9, or 10.

## Recommendation

Prioritized actions for detection and mitigation:
* Patch the cockpit-ws package to the vendor-provided security update immediately (see Red Hat Bugzilla ID 2519497).
* Configure network firewalls to restrict access to TCP port 9090 to trusted management networks only to prevent unauthenticated access.
* Monitor webserver logs or network traffic for anomalous volumes of requests targeting the Cockpit login path from single source IPs.
