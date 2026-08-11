---
title: Kernel Denial of Service Vulnerability in vmxnet3 Driver
slug: 2026-08-vmxnet3-denial-of-service
description: CVE-2026-68299 is a kernel-level denial of service vulnerability in the vmxnet3 virtual network driver caused by a BUG_ON condition when processing malformed Geneve-encapsulated packets.
date: "2026-08-11T10:36:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - kernel
  - infrastructure
vendors:
  - VMware
products:
  - vmxnet3
cves:
  - id: CVE-2026-68299
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68299
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Infrastructure Security
  immediate_actions:
    - action: Patch kernel modules for all virtual machines using vmxnet3.
      owner: IT Operations
      due: 72h
      evidence: Vendor security advisory.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied kernel patches to all affected environments.
      owner: IT Operations
      addresses: CVE-2026-68299
      evidence: Vendor security advisory.
---

CVE-2026-68299 describes a kernel-level vulnerability within the vmxnet3 virtual network driver. The issue resides in the vmxnet3_get_hdr_len() function, which fails to correctly handle specific Geneve (Generic Network Virtualization Encapsulation) packets. When a malformed or specific crafted packet is received, the driver triggers a kernel BUG_ON condition. Because this occurs within the kernel context, it results in an immediate system crash and denial of service for the affected virtual machine. This vulnerability primarily impacts virtualized environments relying on the vmxnet3 driver for network connectivity in virtualized network overlays that utilize Geneve encapsulation. There is no evidence of remote code execution, but the ease of triggering a system-wide crash via crafted network traffic makes this a relevant availability concern for infrastructure administrators.

## Impact

Successful exploitation of this vulnerability results in a system crash, causing a denial of service for any virtual machine utilizing the vulnerable vmxnet3 driver. This impacts stability in data center environments, particularly those utilizing virtual network overlays or SDN (Software Defined Networking) solutions that leverage Geneve encapsulation.

## Recommendation

Prioritize the deployment of the kernel patch provided by the vendor.
- Review virtualization host and guest kernel logs for kernel panics or BUG_ON events associated with vmxnet3 to identify potential exploitation attempts or accidental triggers.
- Monitor network traffic for anomalous Geneve encapsulated packets directed at high-uptime virtual assets.
