---
title: Twisted DNS Server Denial of Service via Crafted Compression Pointers
slug: 2024-01-twisted-dns-dos
description: A denial-of-service vulnerability exists in the twisted.names module, where an unauthenticated attacker can send a crafted TCP DNS packet with deeply chained compression pointers, causing the Twisted reactor to hang while processing recursive lookups and effectively freezing the server.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - dns
  - twisted
vendors:
  - Twisted
products:
  - Twisted (<= 25.5.0)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.004
    technique_name: 'Application Layer Protocol: DNS'
references:
  - https://github.com/advisories/GHSA-grgv-6hw6-v9g4
  - https://cwe.mitre.org/data/definitions/400.html
  - https://cwe.mitre.org/data/definitions/407.html
  - https://datatracker.ietf.org/doc/html/rfc9267
  - https://github.com/twisted/twisted/blob/trunk/src/twisted/names/dns.py#L595
  - https://github.com/twisted/twisted/commit/e11cd82bdd79b3ebbb0e8635cbb9c76df2b5af09
rules:
  - title: Detect Twisted DNS DoS Attack via Deep Compression Pointers
    description: Detects a potential Denial of Service attack against Twisted DNS servers by identifying DNS packets with excessive compression pointer chains.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - network_connection
      - zeek
  - title: Detect High DNS Question Count
    description: Detects a high number of DNS questions in a single DNS query which might indicate a DNS amplification attack or other malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

The `twisted.names` module is susceptible to a Denial of Service (DoS) attack due to resource exhaustion during DNS name decompression. This vulnerability allows a remote, unauthenticated attacker to exploit the system by sending a crafted TCP DNS packet containing deeply chained compression pointers. This bypasses existing loop-prevention mechanisms and leads to the single-threaded Twisted reactor becoming unresponsive as it processes millions of recursive lookups. The vulnerability was introduced prior to commit e11cd82. The affected package is pip/Twisted (<= 25.5.0), making any service reliant on Twisted for DNS resolution vulnerable. This can paralyze the server, causing significant disruption to services relying on the Twisted framework.

## Attack Chain

1.  Attacker crafts a malicious TCP DNS packet with deeply chained compression pointers. The packet is designed to trigger excessive recursive lookups.
2.  The attacker sends the crafted DNS packet to a vulnerable Twisted DNS server.
3.  The `DNSServerFactory` processes the incoming TCP packet and parses the number of question records (QDCOUNT).
4.  For each question record, the `Message.decode` function calls `Name.decode` to decompress the DNS name.
5.  The `Name.decode` function recursively dereferences the compression pointers, attempting to resolve the name. Due to the crafted chains, the process enters a loop-like behavior.
6.  The lack of a limit on pointer resolutions causes the Twisted reactor's event loop to become blocked.
7.  The server becomes unresponsive to new connections, I/O operations, and existing requests.
8.  The server experiences a Denial of Service (DoS) condition, rendering it effectively paralyzed until the malicious packet processing completes or the process is restarted.

## Impact

A successful attack can render a Twisted-based DNS server unresponsive, leading to a Denial of Service condition. A single malformed TCP packet is sufficient to block the Twisted reactor's event loop for several seconds, or potentially longer, depending on the resources available. The impact is significant because Twisted's single-threaded, cooperative multitasking model makes it vulnerable to such blocking operations. This can affect any service relying on the server for DNS resolution, potentially impacting numerous users and applications.

## Recommendation

*   Update the `twisted.names.dns.Name.decode` function to implement a limit on the number of pointer resolutions allowed per DNS message to address the root cause of the vulnerability.
*   Implement state sharing of the "resolved offset" across all records within a single message to prevent redundant processing of the same compression pointers, mitigating resource exhaustion.
*   Prior to entering the decoding loop in `Message.decode`, validate the number of questions (QDCOUNT) in the DNS packet to avoid processing excessively large question sections.
*   Deploy the Sigma rule `Detect Twisted DNS DoS Attack via Deep Compression Pointers` to identify and alert on the exploitation attempts based on the structure of DNS packets.
