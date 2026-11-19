// UDP 48899 discovery replies (adstool netid / addroute):
// bhf::ads::GetRemoteAddress and AddRemoteRoute -> SendRecv, UDP tag parsing,
// Frame::pop/remove.
//
// Input: u8 op | the datagram the fake router answers with.
#include "fake_ads_server.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	const uint8_t op = in.u8();

	fuzz::FakeUdpServer server(in.bytes(in.n));
	try {
		if (op & 1) {
			bhf::ads::AddRemoteRoute(server.Remote(), fuzz::kRemoteNetId,
						 "192.168.0.1", "fuzz", "Administrator",
						 "1");
		} else {
			AmsNetId netId{};
			bhf::ads::GetRemoteAddress(server.Remote(), netId);
		}
	} catch (const std::exception &) {
	}
	return 0;
}
