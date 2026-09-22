---
title: Heap-Based Buffer Overflow in libslirp DHCPv6 and TFTP Builders
slug: 2026-09-libslirp-heap-overflow
description: A heap-based buffer overflow in libslirp allows a guest VM to trigger memory corruption and potential arbitrary code execution within the host process when small interface MTUs are configured.
date: "2026-09-22T10:35:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:libslirp:libslirp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - heap-overflow
  - virtualization
  - libslirp
vendors:
  - Libslirp
products:
  - libslirp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can trigger this vulnerability to cause a denial-of-service condition or potentially achieve arbitrary code execution within the host process context.
    confidence_band: high
cves:
  - id: CVE-2026-95508
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95508
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit virtualization hosts for non-default MTU configurations
      owner: IT Operations
      due: 72h
      evidence: The default interface MTU is not affected.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade libslirp in all virtualized and containerized environments
      owner: IT Operations
      addresses: CVE-2026-95508
      evidence: NVD vulnerability report
---

CVE-2026-95508 describes a heap-based buffer overflow vulnerability residing in the DHCPv6 and TFTP response builders within the libslirp library. The vulnerability is triggered when the host network interface is configured with an unusually small Maximum Transmission Unit (MTU). Under these conditions, the library fails to properly validate the length of guest-supplied DHCPv6 CLIENTID options or TFTP blksize options. By providing malformed options, an attacker within a guest virtual machine can overflow the reply buffer with controlled content and length. This flaw impacts the host process context, enabling potential denial of service or arbitrary code execution. Systems utilizing the default interface MTU are not susceptible to this specific overflow. This vulnerability highlights the risks associated with guest-to-host interface boundary validation in virtualized network stacks.

## Impact

Successful exploitation allows a malicious actor operating within a guest virtual machine to compromise the host process hosting the libslirp instance. This can result in a crash leading to denial of service for network services or, in scenarios where the heap layout is predictable, arbitrary code execution with the privileges of the host process. The vulnerability affects environments using non-default, small MTU configurations, which may be common in specific containerized or restricted network segments.

## Recommendation

Identify and update all virtualization environments or applications embedding libslirp to a patched version once released by the maintainers. Prioritize systems where non-default MTU settings are applied to virtual network interfaces. Review virtualization configurations to enforce safe MTU defaults and implement network micro-segmentation to restrict the ability of untrusted guests to interact with sensitive TFTP or DHCPv6 management services. Monitor host process memory behavior for abnormal crash patterns or unexpected child process spawning related to networking components.
