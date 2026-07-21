---
title: BusyBox AWK Vulnerability Leads to Denial of Service
slug: 2026-07-busybox-awk-dos
description: A stack overflow vulnerability, identified as CVE-2026-38752, exists in the evaluate() function within the AWK editor (editors/awk.c) of BusyBox commit 371fe9, which allows attackers to trigger a Denial of Service (DoS) condition by providing a specially crafted AWK script.
date: "2026-07-21T07:29:56Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:busybox:busybox:2024-07-13:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - linux
  - busybox
vendors:
  - BusyBox
products:
  - BusyBox (commit 371fe9)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A stack overflow in the evaluate() function... allows attackers to cause a Denial of Service (DoS) via supplying a crafted AWK script.
    confidence_band: high
cves:
  - id: CVE-2026-38752
    cvss: 2.9
    epss: 0.00307
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-38752
---

A significant stack overflow vulnerability, tracked as CVE-2026-38752, has been discovered in the `evaluate()` function of BusyBox's AWK utility. This flaw specifically affects BusyBox commit 371fe9 and resides within the `editors/awk.c` source file. Attackers can exploit this vulnerability by supplying a carefully crafted AWK script to the BusyBox AWK interpreter. Successful exploitation leads to a Denial of Service (DoS) condition on the affected system, causing the BusyBox process, and potentially the entire system if critical services rely on it, to crash or become unresponsive. Given BusyBox's widespread use in embedded systems, IoT devices, and various Linux environments, this vulnerability could impact a broad range of devices and services. The vulnerability's impact stems from resource exhaustion caused by the stack overflow, making the targeted system unreliable or unavailable.

## Attack Chain

1. An attacker gains the ability to execute an AWK script on a target system running an affected version of BusyBox. This could be through a web application accepting user-provided scripts, a compromised user account, or other means of remote execution.
2. The attacker crafts a malicious AWK script designed to trigger a stack overflow within the `evaluate()` function in `editors/awk.c`.
3. The crafted AWK script is provided as input to the BusyBox AWK interpreter.
4. During the script's execution, the `evaluate()` function is called.
5. The malicious script's input causes recursive or deeply nested operations within `evaluate()`, leading to excessive stack memory consumption.
6. The stack overflow occurs, corrupting memory and causing the BusyBox AWK process to crash or become unresponsive.
7. The system experiences a Denial of Service, affecting services or the entire device relying on the BusyBox utility.

## Impact

Successful exploitation of CVE-2026-38752 results in a Denial of Service (DoS) condition on systems running affected BusyBox versions. This can manifest as the BusyBox process crashing or freezing, rendering services dependent on it inoperable. In embedded systems or IoT devices where BusyBox is a core component, this could lead to device unresponsiveness, requiring manual intervention such as a reboot. The primary impact is system instability and unavailability. While no specific victim counts or sectors are currently identified, the broad deployment of BusyBox in various critical infrastructure, industrial control systems, and consumer devices means the potential for widespread disruption exists.

## Recommendation

* Patch CVE-2026-38752 by upgrading BusyBox to a version that includes the fix for the stack overflow vulnerability.
* Restrict the execution of user-supplied or untrusted AWK scripts on systems using BusyBox to mitigate the attack vector for CVE-2026-38752.
* Monitor system logs for unexpected BusyBox process crashes or restarts, which could indicate attempts to exploit CVE-2026-38752.
