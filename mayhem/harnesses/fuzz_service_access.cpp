// The small fixed-struct response decoders behind adstool license|ecat|
// dc-diag|pciscan|sysserv: LicenseAccess, ECatAccess, MasterDcStatAccess,
// RouterAccess, SysServAccess.
//
// Input: u8 service | u64 pci id | server replies.
#include "fake_ads_server.h"
#include "ECatAccess.h"
#include "LicenseAccess.h"
#include "MasterDcStatAccess.h"
#include "RouterAccess.h"
#include "SysServAccess.h"

#include <sstream>

template <typename Access, typename F>
static void Run(const std::string &gw, F f)
{
	Access access{ gw, fuzz::kRemoteNetId, 0 };
	f(access);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t service = in.u8();
	uint64_t pciId = in.u32();
	pciId = (pciId << 32) | in.u32();

	fuzz::FakeAdsServer server(in);
	const auto gw = server.Gateway();
	std::ostringstream os;
	try {
		using namespace bhf::ads;
		switch (service % 9) {
		case 0:
			Run<LicenseAccess>(gw, [&](LicenseAccess &a) { a.ShowOnlineInfo(os); });
			break;
		case 1:
			Run<LicenseAccess>(gw, [&](LicenseAccess &a) { a.ShowPlatformId(os); });
			break;
		case 2:
			Run<LicenseAccess>(gw, [&](LicenseAccess &a) { a.ShowSystemId(os); });
			break;
		case 3:
			Run<LicenseAccess>(gw, [&](LicenseAccess &a) { a.ShowVolumeNo(os); });
			break;
		case 4:
			Run<ECatAccess>(gw, [&](ECatAccess &a) { a.ListECatMasters(os); });
			break;
		case 5:
			Run<MasterDcStatAccess>(gw, [&](MasterDcStatAccess &a) { a.Print(os); });
			break;
		case 6:
			Run<MasterDcStatAccess>(gw, [&](MasterDcStatAccess &a) { a.Activate(); });
			break;
		case 7:
			Run<RouterAccess>(gw, [&](RouterAccess &a) { a.PciScan(pciId, os); });
			break;
		default:
			// timeout 0: no polling loop / sleeps, just the state reads
			Run<SysServAccess>(gw, [&](SysServAccess &a) { a.Reconfig(0); });
			break;
		}
	} catch (const std::exception &) {
	}
	return 0;
}
