---
title: LuCI DHCPv6 Lease Hostname Stored Cross-Site Scripting Vulnerability (CVE-2026-61876)
slug: 2026-07-luci-dhcpv6-xss
description: LuCI versions are vulnerable to CVE-2026-61876, a stored Cross-Site Scripting (XSS) flaw in their DHCPv6 lease hostname rendering logic, allowing an adjacent network attacker to inject malicious HTML markup that executes in an administrator's browser when viewing DHCP lease status pages.
date: "2026-07-12T12:26:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - network-device
  - router
  - dhcpv6
vendors:
  - OpenWrt
products:
  - LuCI
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can send a DHCPv6 Client FQDN containing script tags that execute in the administrator's browser when viewing DHCP lease pages.
    confidence_band: high
cves:
  - id: CVE-2026-61876
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61876
  - https://github.com/openwrt/luci/security/advisories/GHSA-686p-p8p9-x6fh
  - https://www.vulncheck.com/advisories/luci-dhcpv6-lease-hostname-stored-cross-site-scripting
---

CVE-2026-61876 identifies a high-severity stored Cross-Site Scripting (XSS) vulnerability affecting LuCI, the default web interface for OpenWrt-based routers and network devices. This flaw arises from LuCI's failure to properly encode DHCPv6 lease hostnames before displaying them in administrative status tables. An attacker with adjacent network access can craft a malicious DHCPv6 Client FQDN containing script tags or other HTML markup. When an administrator subsequently views the DHCPv6 lease status page within the LuCI web interface, the injected malicious code executes in their browser. This client-side code execution can lead to various compromises within the administrative session, including session hijacking, credential theft, or unauthorized actions within the LuCI interface.

## Attack Chain

1. An attacker gains presence on the same adjacent network segment as the vulnerable LuCI-managed OpenWrt device.
2. The attacker crafts a DHCPv6 Client Fully Qualified Domain Name (FQDN) containing a malicious XSS payload, such as `<script>alert(document.domain)</script>`.
3. The attacker sends a DHCPv6 request to the OpenWrt device, including the malicious FQDN in the request.
4. The OpenWrt device, running the LuCI web interface, processes the DHCPv6 request and stores the malicious FQDN in its internal DHCP lease table.
5. An administrator logs into the LuCI web interface and navigates to the DHCPv6 lease status page to view network client information.
6. The LuCI web interface queries the stored DHCP lease data, retrieves the malicious FQDN, and constructs an HTML response for the administrator's browser.
7. Due to improper encoding, LuCI embeds the attacker's malicious FQDN directly into the HTML without sanitization.
8. The administrator's browser renders the page, executing the injected script within the context of the LuCI administrative interface, potentially leading to session hijacking or further compromise.

## Impact

Successful exploitation of CVE-2026-61876 results in client-side code execution within an administrator's browser while they are logged into the LuCI web interface. This can lead to session hijacking, allowing the attacker to take over the administrator's session and perform actions on the OpenWrt device. Attackers could also steal credentials, deface the administrative interface, or redirect the administrator to malicious websites. Such compromise of a router's administrative interface could grant attackers control over network configuration, traffic routing, and potentially provide a foothold for further attacks against the internal network.

## Recommendation

* Patch CVE-2026-61876 by updating LuCI to a version that properly encodes DHCPv6 lease hostnames. Refer to the OpenWrt project's advisories for specific version updates.
* Implement network segmentation to restrict DHCPv6 requests to trusted devices and prevent adjacent network attackers from reaching the router's DHCP service.
* Educate administrators on the risks of XSS and suspicious behavior when interacting with web interfaces, even trusted ones.
