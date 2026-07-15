---
title: RabbitMQ Management UI UNC SSRF Vulnerability (CVE-2026-57211) on Windows
slug: 2026-07-rabbitmq-unc-ssrf
description: CVE-2026-57211 details a Server-Side Request Forgery (SSRF) vulnerability within the RabbitMQ management UI when deployed on Windows, enabling an attacker to coerce the server into making requests to arbitrary UNC paths, potentially leading to NTLM credential disclosure or internal network reconnaissance.
date: "2026-07-15T07:47:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:broadcom:rabbitmq_server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - rabbitmq
  - windows
  - msrc
vendors:
  - VMware
products:
  - RabbitMQ management UI
affected_os:
  - Windows
cves:
  - id: CVE-2026-57211
    cvss: 6.5
    epss: 0.00404
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57211
---

CVE-2026-57211, disclosed by Microsoft, describes a Server-Side Request Forgery (SSRF) vulnerability specifically affecting the RabbitMQ management UI when hosted on Windows operating systems. This vulnerability allows an unauthenticated remote attacker to craft requests that force the vulnerable RabbitMQ server to initiate outbound connections to arbitrary Universal Naming Convention (UNC) paths. This critical flaw could enable attackers to perform NTLM credential relay attacks by pointing the server to a malicious SMB share, leading to credential theft, or to conduct internal network reconnaissance by attempting connections to various internal network resources via UNC paths. While the advisory does not specify observed exploitation, the nature of SSRF in a management interface presents a significant risk to internal network security. Organizations utilizing RabbitMQ on Windows are strongly advised to review and apply the necessary security updates.

## Attack Chain

1. An unauthenticated remote attacker identifies a RabbitMQ instance running its management UI on a Windows server.
2. The attacker crafts a malicious HTTP request to the RabbitMQ management UI.
3. This crafted request includes a parameter or payload designed to trigger the Server-Side Request Forgery (SSRF) vulnerability.
4. The vulnerability causes the RabbitMQ server to attempt to initiate an outbound network connection to an attacker-controlled Universal Naming Convention (UNC) path (e.g., `\\attacker-ip\share`).
5. If the attacker controls an SMB server at the specified UNC path, the Windows server hosting RabbitMQ will attempt NTLM authentication, sending its hashed credentials.
6. The attacker captures these NTLM hashes, which can then be cracked offline or used in NTLM relay attacks to gain unauthorized access to other services or systems within the internal network.

## Impact

Successful exploitation of CVE-2026-57211 can lead to significant information disclosure and potential lateral movement within an organization's network. Attackers can leverage the SSRF to force the RabbitMQ server to connect to arbitrary internal or external UNC paths. This can result in NTLM credential leakage, where the server's NTLM hash is sent to an attacker-controlled SMB share, allowing for offline cracking or NTLM relay attacks. Furthermore, the ability to make arbitrary outbound connections can be used for internal network reconnaissance, mapping network topologies, and identifying other vulnerable services or devices, escalating the potential for further compromise.

## Recommendation

* Apply the security update addressing CVE-2026-57211 released by VMware immediately to all affected RabbitMQ installations running on Windows.
* Restrict outbound network connections from RabbitMQ servers to only necessary and trusted destinations to mitigate the impact of SSRF vulnerabilities.
* Implement host-based firewalls or network segmentation to prevent RabbitMQ servers from initiating SMB connections to arbitrary UNC paths or untrusted internal hosts.
