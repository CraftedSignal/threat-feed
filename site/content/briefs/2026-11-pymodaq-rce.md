---
brief_id: brief-2026-11-05-pymodaq-rce
event_id: brief-2026-11-05-pymodaq-rce
revision: 1
activity_at: "2026-11-05T20:29:23Z"
title: 'PyMoDAQ: Arbitrary code execution via insecure deserialization and eval injection (CVE-2026-120859)'
slug: 2026-11-pymodaq-rce
description: Multiple PyMoDAQ components are vulnerable to insecure deserialization and eval injection, allowing attackers to execute arbitrary code via crafted HDF5, .dock, or XML settings files.
date: "2026-11-05T20:29:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
vendors:
  - PyMoDAQ
products:
  - PyMoDAQ (< 4.4.13)
  - pymodaq_data (< 5.1.15, 5.2.x < 5.2.14, 5.3.x < 5.3.10)
  - pymodaq_gui (< 5.1.15, 5.2.x < 5.2.14, 5.3.x < 5.3.10)
  - pymodaq_utils (< 5.1.15, 5.2.x < 5.2.14, 5.3.x < 5.3.10)
cves:
  - id: CVE-2026-120859
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120859
---

PyMoDAQ (before 4.4.13) and associated components (pymodaq_data, pymodaq_gui, and pymodaq_utils before 5.1.15, 5.2.x before 5.2.14, and 5.3.x before 5.3.10) contain deserialization of untrusted data and eval injection vulnerabilities. These flaws allow attackers to execute arbitrary code by supplying crafted files that a user opens. 

Exploitation vectors include:
- HDF5 string nodes processed by StringARRAY.array_to_string() using pickle.loads().
- HDF5 attributes processed by JsonConverter.json2object().
- .dock files processed by load_layout_state() using unpickling.
- XML settings files processed by elt_to_dict() and set_txt_from_elt().
