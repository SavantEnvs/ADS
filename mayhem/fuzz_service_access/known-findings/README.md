# uncontrolled allocation in LicenseAccess::ShowOnlineInfo

`oom-*`: found by `fuzz_service_access` (service 0, `adstool license onlineinfo`).

- **Where:** `AdsLib/LicenseAccess.cpp:130`: `std::vector<TcLicenseOnlineInfo>(licenseCount)` with
  `licenseCount` taken verbatim from the device's reply.
- **Impact:** a malicious/broken ADS peer makes the client allocate up to 4 G × sizeof(entry)
  (≈137 GB) → OOM / `std::bad_alloc` abort.
- **Fix:** bound `licenseCount` (e.g. by a sane maximum or by the reply size limit) before allocating.
