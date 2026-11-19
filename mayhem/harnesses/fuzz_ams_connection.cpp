// AMS/AoE receive path: AmsConnection::Recv/ReceiveFrame/ReceiveNotification,
// RingBuffer and NotificationDispatcher sample parsing, driven through the
// public C API (AdsSync*ReqEx*) the way any AdsLib application uses it.
//
// Input: 8 bytes of client script (which request to issue next), then the
// fake router's replies (see fake_ads_server.h).
#include "fake_ads_server.h"

#include <array>

static void Callback(const AmsAddr *, const AdsNotificationHeader *pNotification,
		     uint32_t)
{
	// Touch every sample byte the library claims to hand us.
	const auto *data = reinterpret_cast<const volatile uint8_t *>(pNotification + 1);
	uint8_t sink = 0;
	for (uint32_t i = 0; i < pNotification->cbSampleSize; ++i) {
		sink ^= data[i];
	}
	(void)sink;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz::Init();
	fuzz::Input in{ data, size };
	std::array<uint8_t, 8> script{};
	for (auto &op : script) {
		op = in.u8();
	}

	fuzz::FakeAdsServer server(in);
	if (bhf::ads::AddLocalRoute(fuzz::kRemoteNetId, server.Gateway().c_str())) {
		bhf::ads::DelLocalRoute(fuzz::kRemoteNetId);
		return 0;
	}
	const long port = AdsPortOpenEx();
	const AmsAddr addr{ fuzz::kRemoteNetId, AMSPORT_R0_PLC_TC3 };

	uint32_t hNotify = 0;
	const AdsNotificationAttrib attrib{ 4, ADSTRANS_SERVERONCHA, 0, { 0 } };
	const bool haveNotify =
		!AdsSyncAddDeviceNotificationReqEx(port, &addr, 0x4020, 0, &attrib,
						   &Callback, 0, &hNotify);

	std::array<uint8_t, 256> buf{};
	uint32_t bytesRead = 0;
	for (const auto op : script) {
		const uint32_t len = 1 + (op >> 3) * 8; // 1..249
		switch (op & 7) {
		case 0: {
			char name[16 + 1] = {};
			AdsVersion version{};
			AdsSyncReadDeviceInfoReqEx(port, &addr, name, &version);
			break;
		}
		case 1: {
			uint16_t ads = 0, dev = 0;
			AdsSyncReadStateReqEx(port, &addr, &ads, &dev);
			break;
		}
		case 2:
			AdsSyncReadReqEx2(port, &addr, 0x4020, op, len, buf.data(),
					  &bytesRead);
			break;
		case 3:
			AdsSyncReadWriteReqEx2(port, &addr, 0xF003, 0, len,
					       buf.data(), 4, "MAIN", &bytesRead);
			break;
		case 4:
			AdsSyncWriteReqEx(port, &addr, 0x4020, 0, len, buf.data());
			break;
		case 5:
			AdsSyncWriteControlReqEx(port, &addr, ADSSTATE_RUN, 0, 0,
						 nullptr);
			break;
		case 6: {
			uint32_t h = 0;
			if (!AdsSyncAddDeviceNotificationReqEx(port, &addr, 0x4020, 4,
							       &attrib, &Callback, 1,
							       &h)) {
				AdsSyncDelDeviceNotificationReqEx(port, &addr, h);
			}
			break;
		}
		default:
			AdsSyncReadReqEx2(port, &addr, 0x4020, 0, len, buf.data(),
					  nullptr);
			break;
		}
	}
	if (haveNotify) {
		AdsSyncDelDeviceNotificationReqEx(port, &addr, hNotify);
	}
	AdsPortCloseEx(port);
	bhf::ads::DelLocalRoute(fuzz::kRemoteNetId);
	return 0;
}
