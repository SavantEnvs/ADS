# uncontrolled allocation in SymbolAccess::FetchSymbolEntries

`oom-*`: found by `fuzz_symbol_access` (`adstool plc show-symbols|read-symbol|write-symbol`).

- **Where:** `AdsLib/SymbolAccess.cpp:130`: `std::vector<uint8_t> symbols(uploadInfo.nSymSize)` with
  `nSymSize` taken verbatim from the PLC's `ADSIGRP_SYM_UPLOADINFO` reply.
- **Impact:** a malicious ADS peer makes the client allocate up to 4 GiB per request → OOM.
- **Fix:** cap `nSymSize` to a sane maximum before allocating.
