---
title: PowerDNS Denial of Service Vulnerability
slug: 2026-08-powerdns-dos
description: A vulnerability in PowerDNS Authoritative Server and Recursor allows an unauthenticated remote attacker to trigger a denial of service condition affecting DNS resolution services.
date: "2026-08-06T15:20:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - PowerDNS
products:
  - PowerDNS Authoritative Server
  - PowerDNS Recursor
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated, remote attacker can exploit a vulnerability in PowerDNS to perform a Denial of Service attack.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2683
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch PowerDNS software to the latest version provided by the vendor
      owner: IT Operations
      addresses: PowerDNS Authoritative Server and PowerDNS Recursor
      evidence: Source advisory WID-SEC-2026-2683
---

The German Federal Office for Information Security (BSI) has released a security advisory regarding a vulnerability in PowerDNS software, specifically affecting the PowerDNS Authoritative Server and PowerDNS Recursor. An unauthenticated remote attacker can exploit this flaw to cause a Denial of Service (DoS) condition. This vulnerability poses a risk to the availability of infrastructure relying on PowerDNS for name resolution. Organizations utilizing PowerDNS in production environments should review vendor-provided patches and monitor service availability metrics for unexpected restarts or crashes.

## Impact

Successful exploitation results in the disruption of DNS resolution services, which can lead to significant network availability issues for dependent applications, services, and internal infrastructure. Depending on the scale and reach of the affected DNS infrastructure, this could affect internal name resolution or public-facing service availability.

## Recommendation

- Identify all instances of PowerDNS Authoritative Server and PowerDNS Recursor within the network infrastructure.
- Review the vendor-specific security advisory for patched version releases and prioritize the deployment of these updates.
- Monitor service logs and system performance metrics for patterns indicative of process termination or abnormal resource exhaustion.
- Implement network-level rate limiting on DNS traffic to mitigate the impact of potential DoS attempts against exposed DNS resolvers.
