// Shared plumbing for the AdsLib fuzz harnesses.
//
// AdsLib is a client library: the untrusted data is whatever the remote ADS
// router/PLC sends back. The harnesses therefore drive the library's public
// API (the same calls adstool makes) against an in-process loopback "router"
// whose replies come from the fuzz input:
//
//   FakeAdsServer  TCP 48898-style AMS/AoE server on 127.0.0.1:<ephemeral>.
//                  For every request the client writes it consumes one chunk
//                  of the input:   u8 mode | u16le len | len bytes
//                    mode < 0xE0  normal reply: the request's AoE header with
//                                 source/target swapped, state flag RESPONSE,
//                                 same cmdId/invokeId, errorCode 0, and the
//                                 chunk as the AoE payload (result, [read
//                                 length], data ...)
//                    0xE0..0xEF   same, but AoE errorCode = 0x700 + (mode&0xf)
//                    0xF0..0xFF   "raw frame": AmsTcpHeader{len} + the chunk
//                                 verbatim (a whole fuzzer-made AoE frame:
//                                 notifications, wrong ids/ports/commands,
//                                 AoE lengths that disagree with the TCP one)
//                  After a raw frame a well-formed error reply follows, so the
//                  pending request always completes and the client never sits
//                  in its sync timeout (the library default is left alone). Once the input is used up every
//                  further request gets an error reply (the library's loops
//                  all stop on errors, so every run terminates).
//   FakeUdpServer  UDP 48899-style discovery responder: answers the first
//                  datagram with the given bytes.
//
// Per-iteration state: every LLVMFuzzerTestOneInput creates its own server
// socket, route, AMS port and connection and tears all of them down again
// before returning, so no state carries over between inputs. The only
// process-wide settings (log level, local AmsNetId, SIGPIPE ignored) are set
// once in Init() and never changed by an input.
#pragma once

#include "AdsDef.h"
#include "AdsLib.h"
#include "Log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace fuzz
{
static const AmsNetId kRemoteNetId{ 5, 6, 7, 8, 1, 1 };

inline void Init()
{
	static const bool once = [] {
		signal(SIGPIPE, SIG_IGN);
		Logger::logLevel = 4; // silence LOG_* (stderr spam slows fuzzing)
		bhf::ads::SetLocalAddress(AmsNetId{ 192, 168, 0, 1, 1, 1 });
		return true;
	}();
	(void)once;
}

struct Input {
	const uint8_t *p;
	size_t n;

	bool empty() const
	{
		return n == 0;
	}
	uint8_t u8()
	{
		if (!n) {
			return 0;
		}
		--n;
		return *p++;
	}
	uint16_t u16()
	{
		const uint16_t lo = u8();
		return lo | (uint16_t(u8()) << 8);
	}
	uint32_t u32()
	{
		const uint32_t lo = u16();
		return lo | (uint32_t(u16()) << 16);
	}
	std::string bytes(size_t len)
	{
		len = std::min(len, n);
		std::string s(reinterpret_cast<const char *>(p), len);
		p += len;
		n -= len;
		return s;
	}
	// u8 length prefix, at most max bytes
	std::string str(size_t max = 255)
	{
		return bytes(std::min<size_t>(u8(), max));
	}
	// u16le length prefix
	std::string blob()
	{
		return bytes(u16());
	}
};

inline bool WriteAll(int fd, const void *buf, size_t len)
{
	auto p = static_cast<const uint8_t *>(buf);
	while (len) {
		const auto w = send(fd, p, len, MSG_NOSIGNAL);
		if (w <= 0) {
			return false;
		}
		p += w;
		len -= static_cast<size_t>(w);
	}
	return true;
}

inline bool ReadAll(int fd, void *buf, size_t len)
{
	auto p = static_cast<uint8_t *>(buf);
	while (len) {
		const auto r = recv(fd, p, len, 0);
		if (r <= 0) {
			return false;
		}
		p += r;
		len -= static_cast<size_t>(r);
	}
	return true;
}

inline int LoopbackSocket(int type, uint16_t &port)
{
	const int fd = socket(AF_INET, type, 0);
	if (fd < 0) {
		abort();
	}
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	socklen_t len = sizeof(a);
	if (bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) ||
	    getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len)) {
		abort();
	}
	port = ntohs(a.sin_port);
	return fd;
}

class FakeAdsServer {
    public:
	explicit FakeAdsServer(Input in)
		: in_(in)
	{
		listenFd_ = LoopbackSocket(SOCK_STREAM, port_);
		if (listen(listenFd_, 4)) {
			abort();
		}
		thread_ = std::thread(&FakeAdsServer::Run, this);
	}

	// The client (route/AdsDevice) must be gone before this runs: its
	// teardown shuts the connection down, which ends Run().
	~FakeAdsServer()
	{
		shutdown(listenFd_, SHUT_RDWR); // unblocks accept() if never connected
		thread_.join();
		close(listenFd_);
	}

	std::string Gateway() const
	{
		return "127.0.0.1:" + std::to_string(port_);
	}

    private:
	Input in_;
	int listenFd_ = -1;
	uint16_t port_ = 0;
	std::thread thread_;

	static void PutLe32(uint8_t *p, uint32_t v)
	{
		p[0] = v & 0xff;
		p[1] = (v >> 8) & 0xff;
		p[2] = (v >> 16) & 0xff;
		p[3] = (v >> 24) & 0xff;
	}

	static bool SendReply(int fd, const uint8_t *req, uint32_t errorCode,
			      const std::string &payload)
	{
		uint8_t hdr[6 + 32];
		hdr[0] = hdr[1] = 0;
		PutLe32(hdr + 2, static_cast<uint32_t>(32 + payload.size()));
		uint8_t *aoe = hdr + 6;
		memcpy(aoe + 0, req + 8, 8); // target <- request source netid/port
		memcpy(aoe + 8, req + 0, 8); // source <- request target netid/port
		memcpy(aoe + 16, req + 16, 2); // cmdId
		aoe[18] = 0x05; // AMS_RESPONSE
		aoe[19] = 0x00;
		PutLe32(aoe + 20, static_cast<uint32_t>(payload.size()));
		PutLe32(aoe + 24, errorCode);
		memcpy(aoe + 28, req + 28, 4); // invokeId
		std::string frame(reinterpret_cast<const char *>(hdr), sizeof(hdr));
		frame += payload;
		return WriteAll(fd, frame.data(), frame.size());
	}

	bool Reply(int fd, const uint8_t *req)
	{
		static constexpr uint32_t kNoMoreData = 0x701; // ADSERR_DEVICE_SRVNOTSUPP
		if (in_.empty()) {
			return SendReply(fd, req, kNoMoreData, {});
		}
		const uint8_t mode = in_.u8();
		const std::string chunk = in_.blob();
		if (mode < 0xE0) {
			return SendReply(fd, req, 0, chunk);
		}
		if (mode < 0xF0) {
			return SendReply(fd, req, 0x700 + (mode & 0xf), chunk);
		}
		uint8_t tcp[6] = { 0, 0 };
		PutLe32(tcp + 2, static_cast<uint32_t>(chunk.size()));
		const std::string frame =
			std::string(reinterpret_cast<const char *>(tcp), sizeof(tcp)) + chunk;
		return WriteAll(fd, frame.data(), frame.size()) &&
		       SendReply(fd, req, kNoMoreData, {});
	}

	void Run()
	{
		const int fd = accept(listenFd_, nullptr, nullptr);
		if (fd < 0) {
			return;
		}
		// RST on close: no TIME_WAIT pile-up across millions of iterations
		const linger lin{ 1, 0 };
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
		// Replies go out as several small writes; without NODELAY Nagle
		// holds each one back until the client's delayed ACK (~40 ms).
		const int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

		std::vector<uint8_t> req;
		for (;;) {
			uint8_t tcp[6];
			if (!ReadAll(fd, tcp, sizeof(tcp))) {
				break;
			}
			const uint32_t len = tcp[2] | (tcp[3] << 8) |
					     (tcp[4] << 16) |
					     (uint32_t(tcp[5]) << 24);
			if (len > (1u << 24)) {
				break;
			}
			req.resize(len);
			if (!ReadAll(fd, req.data(), len)) {
				break;
			}
			if (len < 32) {
				continue;
			}
			if (!Reply(fd, req.data())) {
				break;
			}
		}
		close(fd);
	}
};

class FakeUdpServer {
    public:
	explicit FakeUdpServer(std::string reply)
		: reply_(std::move(reply))
	{
		fd_ = LoopbackSocket(SOCK_DGRAM, port_);
		thread_ = std::thread(&FakeUdpServer::Run, this);
	}

	~FakeUdpServer()
	{
		if (!answered_) {
			// unblock recvfrom() with a datagram to ourselves
			const int s = socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in a{};
			a.sin_family = AF_INET;
			a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			a.sin_port = htons(port_);
			sendto(s, "", 0, 0, reinterpret_cast<sockaddr *>(&a),
			       sizeof(a));
			close(s);
		}
		thread_.join();
		close(fd_);
	}

	std::string Remote() const
	{
		return "127.0.0.1:" + std::to_string(port_);
	}

    private:
	std::string reply_;
	int fd_ = -1;
	uint16_t port_ = 0;
	std::atomic<bool> answered_{ false };
	std::thread thread_;

	void Run()
	{
		uint8_t buf[2048];
		sockaddr_in from{};
		socklen_t fromLen = sizeof(from);
		if (recvfrom(fd_, buf, sizeof(buf), 0,
			     reinterpret_cast<sockaddr *>(&from),
			     &fromLen) < 0) {
			return;
		}
		answered_ = true;
		// (after a wake-up datagram this answers an already closed socket)
		sendto(fd_, reply_.data(), reply_.size(), 0,
		       reinterpret_cast<sockaddr *>(&from), fromLen);
	}
};
} // namespace fuzz
