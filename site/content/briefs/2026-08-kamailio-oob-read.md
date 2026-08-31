---
title: Out-of-Bounds Read Vulnerability in Kamailio AVP Handler
slug: 2026-08-kamailio-oob-read
description: Kamailio versions up to 5.5.0 and 6.0.7 contain an out-of-bounds read vulnerability in the get_4bytes function that allows remote attackers to trigger memory errors.
date: "2026-08-31T05:14:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:kamailio:kamailio:*:*:*:*:*:*:*:*
vendors:
  - Kamailio
products:
  - Kamailio (<= 5.5.0, 6.0.7)
cves:
  - id: CVE-2026-82608
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82608
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kamailio to version 6.0.8 or later
      owner: IT Operations
      addresses: CVE-2026-82608
      evidence: The vendor points out that version 5.5.0 is old and not maintained anymore.
---

Kamailio versions up to 5.5.0 and 6.0.7 are vulnerable to an out-of-bounds read flaw within the get_4bytes function in the ims_registrar_scscf module (file: src/modules/ims_registrar_scscf/cxdx_avp.c). The AVP Handler component fails to properly validate input during processing, which can be exploited by a remote attacker to induce a crash or potentially leak sensitive memory contents. Publicly available exploit code exists, increasing the risk for environments using unpatched versions of the SIP server. The vendor has highlighted that version 5.5.0 is end-of-life and no longer receives security maintenance, necessitating an upgrade to supported versions for organizations currently relying on these legacy releases.

## Impact

The vulnerability poses a significant risk to SIP-based infrastructure relying on affected versions of Kamailio. Successful exploitation may result in service disruption through denial-of-service or the exposure of sensitive memory data, potentially facilitating further exploitation of the host system.

## Recommendation

- Upgrade Kamailio to a supported version (6.0.8 or later) immediately, as version 5.5.0 is no longer maintained.
- Apply the vendor-provided patch (commit hash: abb5d60af6eefbd367bf6588c5589566b090e272) to custom builds if an immediate upgrade is not feasible.
- Monitor logs for repeated crash events or process restarts in the Kamailio service, which may indicate attempts to trigger memory instability via this vulnerability.
