---
title: OpenSSH sshd Denial-of-Service via GSSAPI Authentication (CVE-2026-60000)
slug: 2026-07-openssh-dos
description: A high-severity denial-of-service vulnerability, CVE-2026-60000, affects OpenSSH versions prior to 10.4, allowing remote attackers to exhaust server resources through excessive and mishandled GSSAPI authentication attempts, leading to service unavailability.
date: "2026-07-09T07:42:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - ssh
  - openssh
  - network-attack
vendors:
  - OpenSSH Project
products:
  - OpenSSH < 10.4
  - sshd
cves:
  - id: CVE-2026-60000
    cvss: 3.7
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-60000
---

A significant denial-of-service (DoS) vulnerability, identified as CVE-2026-60000, has been disclosed affecting the `sshd` component of OpenSSH. This flaw impacts all OpenSSH versions before 10.4. Attackers can exploit this vulnerability remotely by initiating excessive authentication attempts specifically utilizing the GSSAPI authentication mechanism. The `sshd` service mishandles the `MaxAuthTries` configuration for GSSAPIAuthentication, failing to properly limit or terminate these attempts. This oversight allows a malicious actor to continuously flood the server with GSSAPI requests, consuming disproportionate system resources such as CPU and memory, thereby causing the `sshd` service, and potentially the entire host system, to become unresponsive. The vulnerability is particularly concerning due to its ease of exploitation and potential for widespread disruption in environments relying on OpenSSH for secure remote access.

## Attack Chain

1. An attacker identifies an internet-facing server running a vulnerable version of OpenSSH `sshd` (prior to 10.4).
2. The attacker initiates a remote SSH connection to the target server, typically on port 22.
3. During the authentication phase, the attacker specifically attempts to authenticate using the GSSAPI mechanism.
4. The vulnerable OpenSSH `sshd` daemon processes the incoming GSSAPI authentication requests.
5. Due to the mishandling of the `MaxAuthTries` configuration for GSSAPIAuthentication (CVE-2026-60000), the server fails to properly count, limit, or terminate these authentication attempts.
6. The attacker leverages this bypass by repeatedly sending a high volume of GSSAPI authentication attempts to the target server in rapid succession.
7. The continuous, unmitigated processing of these excessive requests consumes a significant amount of the target server's CPU and memory resources.
8. The resource exhaustion ultimately leads to the OpenSSH `sshd` service becoming unresponsive, preventing legitimate users from establishing SSH connections and causing a complete denial of service.

## Impact

Successful exploitation of CVE-2026-60000 results in a severe denial of service, rendering the affected OpenSSH server inaccessible to legitimate users. This can lead to significant operational disruption for organizations that rely on SSH for remote administration, file transfers, and other critical services. The impact can range from temporary unavailability of specific services to a complete outage of the host system, depending on the severity of resource exhaustion. While no specific victim counts or targeted sectors have been disclosed, any organization using vulnerable OpenSSH versions is at risk, potentially affecting thousands of servers globally.

## Recommendation

* Prioritize patching CVE-2026-60000 by updating all OpenSSH installations to version 10.4 or later immediately.
* Monitor SSH server logs for an unusually high volume of failed GSSAPI authentication attempts from single source IPs to identify potential exploitation attempts.
* Implement network-level rate limiting or intrusion prevention system (IPS) rules to detect and block excessively high rates of SSH connection attempts targeting port 22, especially those initiating GSSAPI authentication.
