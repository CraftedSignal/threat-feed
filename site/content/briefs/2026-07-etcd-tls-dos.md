---
title: etcd TLS Listener Denial of Service Vulnerability
slug: 2026-07-etcd-tls-dos
description: A denial-of-service vulnerability in etcd's TLS listener allows a network attacker to exhaust server memory by spawning unbounded goroutines through multiple TCP connections without sending ClientHello messages, leading to loss of availability for etcd clusters and dependent services like Kubernetes.
date: "2026-07-24T22:43:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - etcd
  - denial-of-service
  - kubernetes
  - TLS
vendors:
  - etcd project
products:
  - etcd (< 3.5.33)
  - etcd (>= 3.6.0, < 3.6.14)
  - etcd (>= 3.7.0-alpha.0, < 3.7.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A network attacker who can reach an etcd TLS listener can open many TCP connections and never send a ClientHello. Each connection spawns a goroutine in the etcd server process that blocks indefinitely inside tls.Conn.Handshake(), and each is tracked in the pending map. Unbounded goroutine and map growth exhausts memory in the etcd process, causing loss of availability for the etcd cluster (and, when etcd backs Kubernetes, the control plane).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6vch-q96h-7gc3
---

A critical denial-of-service vulnerability (GHSA-6vch-q96h-7gc3) exists in etcd's TLS listener, allowing a remote network attacker to render etcd clusters unavailable. This flaw, discovered and reported by VMware By Broadcom, affects etcd versions prior to 3.5.33, 3.6.0 through 3.6.13, and 3.7.0-alpha.0 through 3.7.0. The vulnerability stems from etcd's `tlsListener.acceptLoop` component, which spawns an unbounded number of goroutines when handling incoming TCP connections that do not proceed with a TLS ClientHello message. Each uncompleted handshake consumes server memory indefinitely, leading to memory exhaustion and subsequent denial of service for the etcd process. This directly impacts the availability of etcd-backed services, most notably the control plane for Kubernetes deployments.

## Attack Chain

1. A network attacker establishes numerous TCP connections to a vulnerable etcd TLS listener on the target server.
2. The attacker intentionally refrains from sending the expected TLS ClientHello message after initial TCP connection establishment for each new connection.
3. For every incoming TCP connection, the etcd server's `tlsListener.acceptLoop` component spawns a dedicated goroutine to manage the TLS handshake.
4. Each spawned goroutine attempts to perform a TLS handshake and consequently enters a blocking state within `tls.Conn.Handshake()`, waiting indefinitely for the absent ClientHello message.
5. The etcd process's internal pending map tracks these blocked goroutines and their associated connection states, leading to an uncontrolled increase in entries.
6. As the attacker maintains open, incomplete connections, the number of blocked goroutines and the size of the internal pending map grow without bound.
7. This uncontrolled growth continuously consumes increasing amounts of memory within the etcd server process, eventually leading to memory exhaustion.
8. The etcd server process crashes or becomes unresponsive, resulting in a denial of service for the etcd cluster and its dependent services, such as a Kubernetes control plane.

## Impact

Successful exploitation of this vulnerability leads to a complete loss of availability for the targeted etcd cluster due to memory exhaustion and subsequent process crashes. Organizations using affected etcd versions, particularly those relying on etcd as the backend for their Kubernetes control planes, are at risk. A denial of service for etcd directly impacts the operational status and management capabilities of Kubernetes, potentially rendering clusters inoperable until the etcd instance is restored or patched. There are no specific victim counts or sectors mentioned, but any organization using etcd is potentially vulnerable.

## Recommendation

* Upgrade etcd to a patched version immediately to remediate the vulnerability (etcd 3.7.1, 3.6.14, or 3.5.33).
* Restrict network access to etcd's client (gRPC) port for vulnerable versions using firewall rules or network policy to limit potential attackers.
