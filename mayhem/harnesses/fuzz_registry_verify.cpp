// bhf::ads::RegistryAccess::Verify (adstool registry verify < file.reg):
// the offline .reg file parser and its re-serialisation. No network.
#include "fake_ads_server.h"
#include "RegistryAccess.h"

#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	std::istringstream is(std::string(reinterpret_cast<const char *>(data), size));
	std::ostringstream os;
	try {
		bhf::ads::RegistryAccess::Verify(is, os);
	} catch (const std::exception &) {
	}
	return 0;
}
