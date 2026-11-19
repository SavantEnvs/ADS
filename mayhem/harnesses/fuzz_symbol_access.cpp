// bhf::ads::SymbolAccess (adstool plc show-symbols|read-symbol|write-symbol):
// symbol upload info + symbol table parsing (SymbolEntry::Parse), JSON output,
// typed reads/writes of a symbol.
//
// Input: u8 op | u8-prefixed symbol name | u8-prefixed value | server replies.
#include "fake_ads_server.h"
#include "SymbolAccess.h"

#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t op = in.u8();
	const std::string name = in.str(64);
	const std::string value = in.str(32);

	fuzz::FakeAdsServer server(in);
	try {
		bhf::ads::SymbolAccess symbols{ server.Gateway(), fuzz::kRemoteNetId, 0 };
		std::ostringstream os;
		switch (op % 3) {
		case 0:
			symbols.ShowSymbols(os);
			break;
		case 1:
			symbols.Read(name, os);
			break;
		default:
			symbols.Write(name, value);
			break;
		}
	} catch (const std::exception &) {
	}
	return 0;
}
