// bhf::ads::RegistryAccess over ADS (adstool registry export|import):
// Enumerate, RegistryEntry::Create(buffer, ...) from network replies,
// Write/WriteEscaped, and Import's .reg parsing + writes.
//
// Input: u8 op | u8-prefixed key | u16-prefixed .reg text (import) | replies.
#include "fake_ads_server.h"
#include "RegistryAccess.h"

#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t op = in.u8();
	const std::string key = in.str(128);
	const std::string regFile = in.blob();

	fuzz::FakeAdsServer server(in);
	try {
		bhf::ads::RegistryAccess reg{ server.Gateway(), fuzz::kRemoteNetId, 0 };
		if (op & 1) {
			std::istringstream is(regFile);
			reg.Import(is);
		} else {
			std::ostringstream os;
			reg.Export(key, os);
		}
	} catch (const std::exception &) {
	}
	return 0;
}
