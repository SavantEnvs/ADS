// AdsFile (adstool file find|read|delete|rename): FindFirst/FindNext
// TcFileFindData handling and recursion, file open/read handles.
//
// Input: u8 op | u8 maxdepth | u8-prefixed path | server replies.
#include "fake_ads_server.h"
#include "AdsFile.h"

#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t op = in.u8();
	const size_t maxdepth = in.u8() % 4;
	const std::string path = in.str(64);

	fuzz::FakeAdsServer server(in);
	try {
		AdsDevice device{ server.Gateway(), fuzz::kRemoteNetId, 10000 };
		std::ostringstream os;
		switch (op % 4) {
		case 0:
			AdsFile::Find(device, path, maxdepth, os);
			break;
		case 1: {
			const AdsFile file{ device, path,
					    bhf::ads::FOPEN::READ |
						    bhf::ads::FOPEN::BINARY |
						    bhf::ads::FOPEN::ENSURE_DIR };
			std::vector<char> buf(4096);
			uint32_t bytesRead;
			do {
				file.Read(buf.size(), buf.data(), bytesRead);
			} while (bytesRead > 0);
			break;
		}
		case 2:
			AdsFile::Delete(device, path,
					bhf::ads::FOPEN::READ |
						bhf::ads::FOPEN::ENABLE_DIR);
			break;
		default:
			AdsFile::Rename(device, path, path + ".bak",
					bhf::ads::FOPEN::ENABLE_DIR);
			break;
		}
	} catch (const std::exception &) {
	}
	return 0;
}
