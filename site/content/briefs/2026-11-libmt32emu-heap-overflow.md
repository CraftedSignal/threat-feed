---
brief_id: brief-2026-11-04-libmt32emu-heap-overflow
event_id: brief-2026-11-04-libmt32emu-heap-overflow
revision: 1
activity_at: "2026-11-04T16:50:02Z"
title: 'libmt32emu: Heap buffer overflow in MidiStreamParserImpl::parseSysex (CVE-2026-121941)'
slug: 2026-11-libmt32emu-heap-overflow
description: A heap-based buffer overflow in libmt32emu allows attackers to corrupt heap memory and crash the application by supplying SysEx messages exceeding 32,768 bytes.
date: "2026-11-04T16:50:02Z"
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
products:
  - libmt32emu (< 2.8.4)
cves:
  - id: CVE-2026-121941
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121941
---

The libmt32emu library before 2.8.4 contains a heap buffer overflow vulnerability in MidiStreamParserImpl::parseSysex. Attackers can write past a heap allocation by supplying oversized, unterminated SysEx messages exceeding 32,768 bytes. This data can be fed through the mt32emu_parse_stream API via MIDI files, ports, or sequencer clients, resulting in heap memory corruption and application crashes.
