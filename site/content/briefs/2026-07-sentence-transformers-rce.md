---
title: Arbitrary Code Execution in sentence-transformers via Logic Flaw
slug: 2026-07-sentence-transformers-rce
description: A security control bypass vulnerability in sentence-transformers (CVE-2026-68770) allows arbitrary code execution during model loading by exploiting a logic flaw in the import_module_class helper.
date: "2026-07-31T21:46:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Hugging Face
products:
  - sentence-transformers
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can achieve arbitrary code execution by placing malicious Python files in a directory that exists on the local filesystem.
    confidence_band: high
cves:
  - id: CVE-2026-68770
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68770
---

The sentence-transformers library contains a security control bypass vulnerability (CVE-2026-68770) that allows attackers to achieve arbitrary code execution. The vulnerability resides in the `import_module_class` helper function within `sentence_transformers/util/misc.py`. A flawed guard condition includes an `or os.path.exists(model_name_or_path)` clause, which forces the trust gate to pass whenever the provided path exists on the local filesystem, effectively ignoring the `trust_remote_code=False` argument.

An attacker who can influence the local filesystem or place files in a directory that a target application subsequently loads can trigger this vulnerability. By placing malicious Python files, such as `modeling_*.py`, and referencing them via a `modules.json` file within the model directory, the attacker ensures that the malicious code executes automatically during the model initialization process. This bypasses the intended security contract, leading to code execution within the context of the process loading the SentenceTransformer model.

## Impact

Successful exploitation results in arbitrary code execution within the process space of any application utilizing the vulnerable sentence-transformers library to load models from untrusted or attacker-influenced local directories. This poses a significant risk to machine learning pipelines, inference servers, and any system that processes externally sourced model data.

## Recommendation

1. Audit applications using `sentence-transformers` to identify locations where models are loaded from directories potentially accessible to unauthorized users.
2. Implement strict filesystem permissions to ensure that model directories cannot be modified by non-privileged accounts.
3. Patch the `sentence-transformers` library to a version where the `import_module_class` logic flaw is remediated.
4. Monitor application logs for unexpected subprocess execution or file system access originating from model-loading service accounts.
