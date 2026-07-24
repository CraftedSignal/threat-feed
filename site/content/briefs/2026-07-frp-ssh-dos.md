---
title: 'frp: Unauthenticated Remote Denial of Service in SSH Tunnel Gateway via Integer Overflow'
slug: 2026-07-frp-ssh-dos
description: An unauthenticated remote denial-of-service vulnerability exists in the frp server's optional SSH Tunnel Gateway (frps) that allows an attacker to crash the entire frps process by sending a specially crafted five-byte message containing an integer overflow value in an SSH `exec` channel request, leading to a sustained service outage.
date: "2026-07-24T21:53:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - vulnerability
  - frp
  - integer-overflow
vendors:
  - fatedier
products:
  - frp (>= 0.53.0, <= 0.70.0)
  - frps server (>= 0.53.0, <= 0.70.0)
  - SSH Tunnel Gateway (>= 0.53.0, <= 0.70.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Application or System Shutdown
    evidence: An integer-overflow vulnerability in the frp server's optional SSH Tunnel Gateway lets any unauthenticated remote attacker crash the entire `frps` process with a single five-byte message.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-26gq-p25f-99cp
---

An integer-overflow vulnerability (CWE-190) has been identified in the frp server's optional SSH Tunnel Gateway (`frps`), affecting versions v0.53.0 through v0.70.0. This flaw allows any unauthenticated remote attacker to trigger a denial of service (DoS) by sending a single, malformed five-byte SSH `exec` channel request. The vulnerability stems from an integer overflow when parsing an attacker-controlled length field (`0xFFFFFFFF`), which causes a Go slice bounds check to fail, leading to an unhandled panic and the termination of the entire `frps` process. Since the attack is pre-authentication and does not require an authorized SSH key, it can be repeatedly exploited to maintain a sustained outage, disrupting all active frp tunnels and preventing new connections. This vulnerability significantly impacts the availability of affected `frps` instances with the SSH Tunnel Gateway enabled, which is not the default configuration.

## Attack Chain

1. An unauthenticated attacker establishes an SSH connection to a vulnerable `frps` server with the SSH Tunnel Gateway explicitly enabled and `AuthorizedKeysFile` unset (default configuration).
2. The attacker opens an SSH session channel.
3. The attacker crafts an `exec` request payload consisting of five bytes.
4. The first four bytes of the payload are set to `0xFFFFFFFF` (32-bit integer).
5. A single arbitrary byte (e.g., `0x41`) follows the four-byte length field.
6. The `frps` server receives the `exec` request payload.
7. During parsing in `pkg/ssh/server.go`, the server adds a constant `4` to the attacker-controlled length `0xFFFFFFFF`. Due to integer overflow, this calculation results in `3`.
8. The subsequent bounds check `len(req.Payload) < int(end)` evaluates to `5 < 3`, which is false, allowing the malicious payload to bypass the check.
9. A slice operation `req.Payload[4:end]` is then executed, which becomes `req.Payload[4:3]`, resulting in a "slice bounds out of range" panic.
10. The unhandled panic causes the entire `frps` process to terminate, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability results in an unauthenticated remote denial of service, causing the `frps` process to crash completely. This crash immediately drops all active tunnels, disconnecting every client and preventing any new connections. The attacker can repeatedly send the malicious five-byte payload to keep the service down indefinitely, making it a sustained outage. While there is no impact on confidentiality or integrity, and no code execution is achieved, the complete loss of service availability can be critical for organizations relying on `frps` for their tunneling infrastructure. This issue specifically affects `frps` instances where the SSH Tunnel Gateway feature is explicitly enabled, as it is disabled by default.

## Recommendation

* Patch affected frp installations immediately to a version beyond `v0.70.0` to remediate the integer overflow vulnerability affecting the SSH Tunnel Gateway.
* If immediate patching is not possible and the SSH Tunnel Gateway is not critical, disable the `sshTunnelGateway` feature in your `frps` configuration to prevent exploitation.
