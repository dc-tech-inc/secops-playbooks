# Detection: Sigma and YARA, tested without malware

| Folder | What | How it is tested |
|---|---|---|
| [`sigma/rules`](sigma/rules) | 3 Sigma rules: PowerShell `-EncodedCommand`, certutil download, EICAR test file written | [`tests/test_sigma.py`](tests/test_sigma.py) runs the pySigma validators, converts each rule to SQL with the official SQLite backend and checks it matches **exactly** the expected events in [`sigma/tests/events.yml`](sigma/tests/events.yml) |
| [`yara/rules`](yara/rules) | EICAR test file, and a canary-document marker for the fictional Example Co. | [`tests/test_yara.py`](tests/test_yara.py) compiles the rules with yara-python, matches the EICAR string (built in memory, never on disk), checks near-misses and benign files |

```bash
pip install -r requirements-ci.txt
pytest detection/tests
```

## Ground rules

- **No malware, ever.** Positive samples are the EICAR test string and synthetic log events whose commands are harmless (the encoded PowerShell decodes to `Write-Output "hello from a drill"`, URLs point at `example.com`).
- Every rule has a positive and a negative case. "Matches exactly the expected events" catches both a rule that stopped firing and a rule that started firing on benign data.
- Every Sigma rule documents `falsepositives` and a `level`, because those decide whether an analyst gets paged.

## Why SQLite for Sigma tests

Sigma is a detection *format*; a rule is only useful once a backend converts it to a query. Converting to SQLite and running the query against a table of events tests the same path a SIEM uses (rule → backend → query → results), with no SIEM. The trade-off: field names here follow Sysmon/Windows conventions without a processing pipeline, so a real deployment still needs the backend and field mapping of the target SIEM.

## Adding a rule

1. Add the rule under `sigma/rules/` with a fresh UUID.
2. Add positive and benign events to `sigma/tests/events.yml` and list the expected matches under `expected`.
3. Run `pytest detection/tests`.

## Limitations

- Three Sigma rules and two YARA rules are a demonstration of the workflow, not detection coverage.
- The SQLite backend implements Sigma modifiers as `LIKE` patterns (case-insensitive for ASCII). SIEM backends can differ on case and regex semantics.

## References

- Sigma rule specification: <https://sigmahq.io/docs/basics/rules.html>
- pySigma and the SQLite backend: <https://github.com/SigmaHQ/pySigma>, <https://github.com/SigmaHQ/pySigma-backend-sqlite>
- YARA, writing rules: <https://yara.readthedocs.io/en/stable/writingrules.html>
- EICAR test file: <https://www.eicar.org/download-anti-malware-testfile/>
- MITRE ATT&CK T1059.001, T1027, T1105: <https://attack.mitre.org/techniques/T1059/001/>
