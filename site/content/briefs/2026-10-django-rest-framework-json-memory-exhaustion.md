---
brief_id: brief-2026-10-29-django-rest-framework-json-memory-exhaustion
event_id: brief-2026-10-29-django-rest-framework-json-memory-exhaustion
revision: 1
activity_at: "2026-10-29T22:22:23Z"
title: 'Django REST framework: JSONParser memory exhaustion via charset parameter'
slug: 2026-10-django-rest-framework-json-memory-exhaustion
description: Django REST framework (DRF) JSONParser fails to validate charset codecs, allowing attackers to bypass DATA_UPLOAD_MAX_MEMORY_SIZE limits through malicious compression, leading to significant memory amplification.
date: "2026-10-29T22:22:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-provided PoC confirms memory amplification behavior
vendors:
  - Django REST framework
products:
  - Django REST framework (>= 3.6.4)
references:
  - https://github.com/advisories/GHSA-3547-9m27-7rxg
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify all services using Django REST framework and verify version
      owner: Detection Engineering
      due: 48h
      evidence: Vulnerability affects all DRF versions >= 3.6.4
  hunt_leads:
    - lead: Identify HTTP POST requests with Content-Type charset parameters indicative of compression codecs
      technique_id: T1059.003
      data_needed:
        - Web server access logs
        - Application request headers
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker supplies charset=bz2_codec or charset=zlib_codec to trigger decompression
  mitigation_plan:
    - priority: immediate
      action: Apply the suggested codec lookup validation check in rest_framework/parsers.py
      owner: IT Operations
      addresses: JSONParser charset codec amplification
      evidence: Source advisory provides one-line patch for parsers.py
---

Django REST framework (DRF) versions 3.6.4 and later contain a vulnerability in `JSONParser` where the `Content-Type` charset parameter is used to apply arbitrary codecs to the request stream. Because DRF does not verify if the requested charset is a valid text encoding, an attacker can specify byte-transform codecs like `bz2_codec` or `zlib_codec`. This results in the request body being decompressed into memory before the `DATA_UPLOAD_MAX_MEMORY_SIZE` check is performed, allowing for massive memory expansion.

## Attack Chain
1. Attacker crafts a highly compressed malicious JSON payload (e.g., 108 bytes).
2. Attacker initiates a POST request to a DRF endpoint accepting JSON.
3. Attacker sets the `Content-Type` header to `application/json; charset=bz2_codec`.
4. Django receives the request and initializes `JSONParser`.
5. `JSONParser` calls `codecs.getreader()` with the attacker-provided `bz2_codec`.
6. The request stream is decompressed into memory by the codec reader.
7. The expanded data is passed to `json.load()` while the original `DATA_UPLOAD_MAX_MEMORY_SIZE` check remains satisfied by the small wire-size of the payload.
8. The worker process consumes significant memory, potentially causing a Denial of Service (DoS).

## Impact
The vulnerability allows an amplification factor of over 400,000x, where a 108-byte request can force the allocation of ~50 MiB of memory, significantly increasing process peak RSS and facilitating memory-based DoS.

## Recommendation
Patch the `JSONParser` to validate that the provided encoding is a supported text-based encoding. Implement the following check within `rest_framework/parsers.py` before invoking the codec:

```python
import codecs
from rest_framework.exceptions import ParseError

if not codecs.lookup(encoding)._is_text_encoding:
 raise ParseError('Unsupported charset in Content-Type')
```

Until patches are applied, monitor for unusual `Content-Type` headers containing non-standard charset parameters in application access logs.
