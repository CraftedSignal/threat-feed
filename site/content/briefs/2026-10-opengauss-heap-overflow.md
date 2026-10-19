---
title: Heap-Based Buffer Overflow in openGauss HllObjectUnpack
slug: 2026-10-opengauss-heap-overflow
description: A heap-based buffer overflow in the HllObjectUnpack function of openGauss-server allows authenticated database users to achieve memory corruption via malformed HyperLogLog (HLL) objects.
date: "2026-10-19T04:57:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opengauss:opengauss-server:*:*:*:*:*:*:*:*
vendors:
  - openGauss
products:
  - openGauss-server (>= 2.1.0, < 7.0.0-LTS)
cves:
  - id: CVE-2026-111441
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111441
  - https://gitcode.com/opengauss/openGauss-server/pull/9380
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DBA Team
  immediate_actions:
    - action: Upgrade openGauss-server to 7.0.0-LTS
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-111441 patch notification
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 7.0.0-LTS
      owner: IT Operations
      addresses: CVE-2026-111441
      evidence: 'Vendor PR #9380'
---

CVE-2026-111441 is a heap-based buffer overflow vulnerability residing in the HllObjectUnpack() function within the openGauss-server codebase (specifically src/gausskernel/cbb/utils/hll/hll.cpp). The vulnerability stems from improper length validation when processing packed HLL objects. The affected function parses 'lenUsed' and 'lenTotal' fields from user-supplied input; however, it fails to verify that 'lenTotal' is greater than or equal to 'lenUsed'. When allocating memory for the HLL object based on the potentially smaller 'lenTotal' and subsequently performing a memory copy using 'memcpy_s', the function uses 'lenUsed' as the destination size instead of the actual buffer size, resulting in an out-of-bounds heap write. This flaw is reachable via standard SQL entry points including hll_in(), hll_print(), and hll_cardinality(). The vulnerability affects versions 2.1.0 through 7.0.0-RC3 and was addressed in the 7.0.0-LTS release. An authenticated database user can leverage this to trigger memory corruption, potentially leading to a crash or arbitrary code execution.

## Impact

Successful exploitation allows an authenticated user with standard database access privileges to trigger memory corruption on the database server. This can lead to service disruption via application crash or potentially remote code execution within the context of the database service. The vulnerability impacts a wide range of versions, including 2.1.0, 3.0.x, 3.1.x, 5.0.x, 5.1.0, 6.0.x, and 7.0.0-RC variants, potentially affecting any enterprise deployment utilizing the HLL utility functions.

## Recommendation

- Upgrade openGauss-server to version 7.0.0-LTS or higher to incorporate the fix for CVE-2026-111441.
- Review the implementation of the HllObjectUnpack() function as described in the fix provided in PR #9380 at https://gitcode.com/opengauss/openGauss-server/pull/9380.
- Audit database access logs to identify users invoking HLL-related functions, as these entry points are necessary to trigger the overflow.
