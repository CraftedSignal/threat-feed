---
brief_id: brief-2026-11-10-maxmpxct-registry
event_id: brief-2026-11-10-maxmpxct-registry
revision: 1
activity_at: "2026-11-10T03:09:13Z"
title: Windows Server SMB MaxMpxCt registry configuration
slug: 2026-11-maxmpxct-registry
description: BlackCat ransomware operators have been observed modifying the "MaxMpxCt" registry value to handle a higher volume of network traffic.
date: "2026-11-10T03:09:13Z"
type: threat
types:
  - threat
severities:
  - low
actors:
  - BlackCat
  - ALPHV
  - Noberus
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
references:
  - https://www.huntress.com/blog/blackcat-ransomware-affiliate-ttps
  - https://web.archive.org/web/20260313001527/https://securityscorecard.com/research/deep-dive-into-alphv-blackcat-ransomware
  - https://www.intrinsec.com/alphv-ransomware-gang-analysis/?cn-reloaded=1
  - https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_optimize_file_sharing_network.yml
---

The "MaxMpxCt" registry value specifies the maximum outstanding network requests for the server per client, used when negotiating a Server Message Block (SMB) connection. Ransomware threat actors and operators (specifically BlackCat) have been observed increasing this value to handle a higher volume of traffic.

## Notes
If the MaxMpxCt value is set beyond 125, older Windows 9x clients will fail to negotiate SMB connections.
