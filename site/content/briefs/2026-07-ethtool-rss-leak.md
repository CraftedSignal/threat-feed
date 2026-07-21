---
title: ethtool RSS Resource Leak on get_rxfh Failure
slug: 2026-07-ethtool-rss-leak
description: A vulnerability, CVE-2026-63999, has been identified in the `ethtool` utility on Linux systems, involving a resource leak of `indir_table` and `hkey` when the `get_rxfh` function related to Receive Side Scaling (RSS) functionality fails, which could lead to system instability or resource exhaustion.
date: "2026-07-21T07:28:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - vulnerability
  - resource-leak
vendors:
  - Linux
products:
  - ethtool
affected_os:
  - Linux
cves:
  - id: CVE-2026-63999
    epss: 0.00166
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63999
---

A vulnerability tracked as CVE-2026-63999 has been discovered in the `ethtool` utility, a standard command-line program used by Linux administrators to query and control network driver and hardware settings. Specifically, this issue affects the Receive Side Scaling (RSS) functionality within `ethtool`, which is a network driver technology that enables the efficient distribution of network receive processing across multiple CPU cores. The vulnerability occurs when the `get_rxfh` function, responsible for retrieving the RSS indirection table (indir_table) and hash key (hkey), fails. Under such failure conditions, the `indir_table` and `hkey` resources are not properly released, leading to a resource leak. While the provided information does not detail a specific exploitation vector, repeated triggering of this failure could deplete system resources, potentially resulting in system instability, performance degradation, or denial of service on affected Linux systems.

## Attack Chain

This brief describes a vulnerability and does not detail an observed attack chain.

## Impact

Successful exploitation of CVE-2026-63999 could lead to system instability, degradation of network performance, or a denial of service condition due to resource exhaustion. As the `indir_table` and `hkey` resources are not properly freed upon `get_rxfh` failure, repeated triggers of this condition would consume increasing amounts of system memory or other critical resources. This could particularly affect systems relying heavily on `ethtool` for network configuration or those where network driver issues frequently lead to `get_rxfh` failures. No specific victim counts or targeted sectors have been identified, as this is a technical vulnerability disclosure rather than an observed exploitation campaign.

## Recommendation

* Patch CVE-2026-63999 immediately by applying the latest security updates to the `ethtool` utility on all affected Linux systems.
* Monitor system resource utilization, especially memory and process counts, on Linux servers to detect potential symptoms of resource exhaustion that could arise from this vulnerability.
