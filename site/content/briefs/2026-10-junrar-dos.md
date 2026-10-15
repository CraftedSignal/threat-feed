---
title: Junrar RARVM Infinite Loop Denial of Service
slug: 2026-10-junrar-dos
description: An infinite loop vulnerability in the Junrar Java library, identified as CVE-2026-97370, allows unauthenticated attackers to cause CPU exhaustion via crafted RAR4 archives.
date: "2026-10-15T22:27:26Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:junrar_project:junrar:*:*:*:*:*:*:*:*
vendors:
  - Junrar
products:
  - junrar (<= 7.6.0)
cves:
  - id: CVE-2026-97370
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-h9h9-2rmf-rvhp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97370
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade junrar library to version > 7.6.0
      owner: IT Operations
      due: 72h
      evidence: Source explicitly identifies version <= 7.6.0 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Implement thread-level timeouts for archive extraction routines
      owner: AppSec
      addresses: CVE-2026-97370
      evidence: Vulnerability causes infinite CPU loops in worker threads.
---

The Junrar Java library is susceptible to a denial-of-service (DoS) condition due to a logic flaw in the RAR virtual machine (RarVM). When processing a specially crafted RAR4 archive, the `RarVM.ExecuteCode` routine can be forced into an infinite loop. This occurs because the `VM_JMP` instruction handler improperly validates jump targets. When a jump target is equal to or greater than the defined `codeSize`, the `setIP()` function returns success without updating the instruction pointer (IP) or decrementing the `maxOpCount` safety counter.

Because the main VM loop continues immediately after the jump without updating these values, the same `VM_JMP` instruction is repeatedly executed. An attacker can exploit this by providing malicious archives to applications using `Junrar.extract()`, leading to permanent hang of extraction worker threads and resource exhaustion. This flaw, tracked as CVE-2026-97370, affects all versions of `junrar` up to and including 7.6.0. The vulnerability is restricted to availability impact and does not grant code execution due to Java's built-in memory protection.

## Attack Chain

1. Attacker crafts a malicious RAR4 archive containing a VM program with a `VM_JMP` instruction.
2. The instruction is configured with a target address that is greater than or equal to the archive's `codeSize`.
3. The victim application invokes `Junrar.extract()` on the uploaded or retrieved malicious RAR archive.
4. The `RarVM` component encounters the crafted `VM_JMP` instruction during the extraction routine.
5. The `setIP()` function validates the target address, returns `true`, but fails to update the `IP` variable.
6. The main VM loop incorrectly ignores the `setIP()` result and executes a `continue` statement, skipping the `maxOpCount` decrement.
7. The VM loop re-executes the same `VM_JMP` instruction indefinitely.
8. The extraction thread consumes 100% CPU, leading to service degradation or process exhaustion.

## Impact

Successful exploitation results in a persistent denial-of-service condition for applications relying on the `junrar` library. In multi-tenant environments or services that process file uploads, this vulnerability can be leveraged to exhaust worker thread pools, preventing the processing of legitimate files. No code execution is documented, but the inability to terminate the extraction loop may require a manual process restart to restore service functionality.

## Recommendation

* Upgrade the `junrar` library to a version greater than 7.6.0 as soon as a patch is available.
* Implement strict size and complexity limits on files processed by archival libraries to mitigate potential DoS vectors.
* Monitor application server thread health and resource utilization for extraction tasks.
* If updating is not immediately possible, implement a watchdog timer or thread timeout for archive extraction routines to force-terminate hung processes.
