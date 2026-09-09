# Test fixtures

`security_4625_failed_logons.evtx` (69,632 bytes)

- Source: EVTX-to-MITRE-Attack corpus, as mirrored in
  `Yamato-Security/hayabusa-sample-evtx` under
  `EVTX-to-MITRE-Attack/TA0001-Initial access/T1078-Valid accounts/`
  ("ID4625-failed login with denied access due to account restriction").
  Original authoring repository: `sbousseaden/EVTX-ATTACK-SAMPLES`.
- Type: real Windows Security log (Microsoft-Windows-Security-Auditing),
  single 64 KiB chunk, two records: Event ID 4625 (failed logon),
  records 90907 and 90939, timestamps 2021-10-23, computer
  `FS03.offsec.lan`.
- The failing account is the anonymous SID (`S-1-0-0`), so
  `TargetUserName` is "-": the parsed `target_user` field is therefore
  absent/empty by design (dash values are treated as "no value").
  `IpAddress` is present: `10.23.23.9` on both records.
- sha256: `06aec213c40fe5eece31c8958d3774381f28e2cd44b7e60f214217a344bc2574`
- Tests must not fetch this file from the network; it is committed.
  The evtx integration tests skip when python-evtx (`[evtx]` extra) is
  not installed; the XML field-parsing unit tests run everywhere.
