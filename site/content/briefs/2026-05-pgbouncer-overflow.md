---
title: Actively Exploited Integer Overflow in PgBouncer (CVE-2026-6664)
slug: 2026-05-pgbouncer-overflow
description: PgBouncer versions prior to 1.25.2 are vulnerable to an integer overflow (CVE-2026-6664), enabling unauthenticated remote attackers to trigger a denial-of-service via a crafted SCRAM authentication packet, with active exploitation reported.
date: "2026-05-20T19:31:08Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:pgbouncer:pgbouncer:*:*:*:*:*:*:*:*
tags:
  - integer overflow
  - denial of service
  - CVE-2026-6664
vendors:
  - PgBouncer
products:
  - PgBouncer < 1.25.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-6664
    cvss: 7.5
    epss: 0.00046
references:
  - https://ccb.belgium.be/advisories/warning-actively-exploited-integer-overflow-pgbouncer-patch-immediately
  - https://www.pgbouncer.org/changelog.html#pgbouncer-125x
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6664
  - https://exploit-intel.com/vuln/CVE-2026-6664
  - https://github.com/nicolasjulian/bouncer-overflow
rules:
  - title: Detect CVE-2026-6664 Exploitation Attempt - Malformed SCRAM Packet
    description: Detects CVE-2026-6664 exploitation attempt — monitors for abnormally large or malformed SCRAM authentication packets sent to PgBouncer instances.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-6664
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

PgBouncer, a widely used open-source connection pooler for PostgreSQL, is affected by an actively exploited integer overflow vulnerability (CVE-2026-6664) in versions prior to 1.25.2. Discovered in early May 2026, this vulnerability allows remote attackers to crash the system without authentication or user interaction. A publicly available proof of concept exists, and reports indicate active exploitation. The vulnerability is located within the network packet processing code and involves an integer overflow, leading to a bypass of boundary checks. Successful exploitation leads to a denial-of-service condition, impacting system availability. Defenders should prioritize patching vulnerable instances and enhance monitoring capabilities.

## Attack Chain

1.  Attacker identifies a vulnerable PgBouncer instance running a version prior to 1.25.2.
2.  Attacker crafts a malicious SCRAM authentication packet specifically designed to trigger the integer overflow.
3.  Attacker sends the crafted SCRAM packet to the vulnerable PgBouncer instance.
4.  PgBouncer processes the packet, and the integer overflow occurs during the handling of network package sizes.
5.  The integer overflow leads to a bypass of boundary checks in the network packet processing logic.
6.  Due to the bypassed boundary checks, the application attempts to access an invalid memory location.
7.  The invalid memory access causes a system crash, resulting in a denial-of-service.
8.  The PgBouncer service becomes unavailable, disrupting applications relying on database connections managed by PgBouncer.

## Impact

Exploitation of CVE-2026-6664 results in a denial-of-service condition, impacting the availability of systems utilizing vulnerable PgBouncer instances. While confidentiality and integrity are not directly affected, the disruption of database connections can severely impact applications and services that rely on PostgreSQL databases. There are reports of active exploitation of this vulnerability. Organizations failing to patch are at risk of service disruption.

## Recommendation

*   Immediately patch all PgBouncer instances to version 1.25.2 or later to remediate CVE-2026-6664 (https://www.pgbouncer.org/changelog.html#pgbouncer-125x).
*   Implement and tune the Sigma rule "Detect CVE-2026-6664 Exploitation Attempt - Malformed SCRAM Packet" to identify potentially malicious SCRAM authentication packets targeting PgBouncer instances.
*   Monitor network traffic for abnormally sized or malformed SCRAM authentication packets directed at PgBouncer instances as described in the vulnerability description.
*   Review the vulnerability details provided by NIST (https://nvd.nist.gov/vuln/detail/CVE-2026-6664) and Exploit-DB (https://exploit-intel.com/vuln/CVE-2026-6664) for more information.
