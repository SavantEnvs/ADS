// bhf::ads::RTimeAccess (adstool rtime read-latency|reset-latency|
// set-shared-cores): CPU settings and latency response validation.
//
// Input: u8 op | u32 shared cores | server replies.
#include "fake_ads_server.h"
#include "RTimeAccess.h"

#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t op = in.u8();
	const uint32_t sharedCores = in.u32();

	fuzz::FakeAdsServer server(in);
	try {
		bhf::ads::RTimeAccess rtime{ server.Gateway(), fuzz::kRemoteNetId, 0 };
		switch (op % 4) {
		case 0:
			rtime.ShowLatency(RTIME_READ_LATENCY);
			break;
		case 1:
			rtime.ShowLatency(RTIME_RESET_LATENCY);
			break;
		case 2:
			rtime.SetSharedCores(sharedCores);
			break;
		default: {
			std::ostringstream os;
			os << rtime.ReadCpuSettings();
			break;
		}
		}
	} catch (const std::exception &) {
	}
	return 0;
}
