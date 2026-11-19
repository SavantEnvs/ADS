# heap-buffer-overflow (read) in ParseHexArchetype

`crash-1054be94…`: found by `fuzz_registry_verify` during integration (same bug reachable from
`fuzz_registry_access` via `RegistryAccess::Import`).

- **Where:** `AdsLib/RegistryAccess.cpp:245`, `ParseHexArchetype()`:
  `prefix.find(it, 0, length)` compares `length = prefix.size()` bytes starting at `it`, but `it`
  points into the current `.reg` line, which may end (NUL) before `length` bytes.
- **Impact:** out-of-bounds heap read on a crafted `.reg` file (`adstool registry verify|import`).
- **Fix:** compare only when enough bytes remain, e.g. `strncmp(it, prefix.c_str(), length) == 0`
  (stops at the line's NUL), instead of `std::string::find` with an explicit length.
