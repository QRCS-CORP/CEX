#include "NetworkTools.h"

NAMESPACE_TOOLS

ipv4_address NetworkTools::GetIPv4Address()
{
	std::string sadd;
	socket_t sock;
	sockaddr_in loopback;
	socklen_t addlen;
	ipv4_address add;

	std::memset(&loopback, 0, sizeof(loopback));
	loopback.sin_family = AF_INET;
	loopback.sin_addr.s_addr = INADDR_LOOPBACK;
	loopback.sin_port = htons(9);
	sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (connect(sock, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)) != SOCKET_RET_ERROR)
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, reinterpret_cast<sockaddr*>(&loopback), &addlen) != SOCKET_RET_ERROR)
		{
			char buf[INET_ADDRSTRLEN];

			if (inet_ntop(AF_INET, &loopback.sin_addr, buf, INET_ADDRSTRLEN) != 0x0)
			{
				sadd.assign(buf, sizeof(buf));
				sadd.erase(std::find(sadd.begin(), sadd.end(), '\0'), sadd.end());
			}
		}
	}

	if (sock != SOCKET_RET_ERROR)
	{
#if defined(CEX_WINDOWS_SOCKETS)
		closesocket(sock);
#else
		close(sock);
#endif
	}

	if (sadd.size() != 0)
	{
		add = ipv4_address::FromString(sadd);
	}

	return add;
}

ipv6_address NetworkTools::GetIPv6Address()
{
	std::string sadd;
	socket_t sock;
	sockaddr_in6 loopback;
	socklen_t addlen;

	std::memset(&loopback, 0, sizeof(loopback));
	loopback.sin6_family = AF_INET6;
	loopback.sin6_addr = in6addr_linklocalprefix;
	loopback.sin6_port = htons(9);
	sock = socket(PF_INET6, SOCK_DGRAM, 0);

	if (connect(sock, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)) != SOCKET_RET_ERROR) //-V641
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, reinterpret_cast<sockaddr*>(&loopback), &addlen) != SOCKET_RET_ERROR)
		{
			char buf[INET6_ADDRSTRLEN];

			if (inet_ntop(AF_INET6, &loopback.sin6_addr, buf, INET6_ADDRSTRLEN) != 0x0)
			{
				sadd.assign(buf, sizeof(buf));
				sadd.erase(std::find(sadd.begin(), sadd.end(), '\0'), sadd.end());
			}
		}
	}

	if (sock != SOCKET_RET_ERROR)
	{
#if defined(CEX_WINDOWS_SOCKETS)
		closesocket(sock);
#else
		close(sock);
#endif
	}

	return ipv6_address::FromString(sadd);
}

ipv4_info NetworkTools::GetIPv4Info(const std::string &Host, const std::string &Service)
{
	ipv4_info info = { 0 };
	sockaddr_in sa;
	std::string sai;
	int32_t res;

	std::memset(&info, 0x00, sizeof(info));
	std::memset(&sa, 0x00, sizeof(sa));

#if defined(CEX_OS_WINDOWS)

	addrinfo* result = nullptr;
	addrinfo hints;

	sa.sin_family = AF_INET;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	result = NULL;

	// resolve the server address and port
	res = getaddrinfo(Host.c_str(), Service.c_str(), &hints, &result);

	if (res == 0)
	{
		char ipstr[INET_ADDRSTRLEN] = { 0 };
		sai.assign(ipstr);
		inet_ntop(AF_INET, &sa.sin_addr, ipstr, INET_ADDRSTRLEN); // fix and test this
		ipv4_address ipa = ipv4_address::FromString(sai);
		info.address = ipa;
		info.port = (uint16_t)ntohs(((struct sockaddr_in*)result->ai_addr)->sin_port);

		if (result != NULL)
		{
			freeaddrinfo(result);
		}
	}



#else

	hostent* lphost;

	sa.sin_len = sizeof(sa);
	sa.sin_addr.s_addr = inet_addr(Host.c_str());
	lphost = gethostbyname(Host.c_str());
	res = lphost != NULL ? 0 : SOCKET_EINVAL;

	if (res == 0)
	{
		sa.sin_addr.s_addr = reinterpret_cast<in_addr*>(lphost->h_addr)->s_addr;
		ipv4_address ipa(reinterpret_cast<uint8_t*>(sa.sin_addr));
		info.address = ipa;
		info.port = sa.sin_port;
	}

#endif

	return info;
}

ipv6_info NetworkTools::GetIPv6Info(const std::string &Host, const std::string &Service)
{
	ipv6_info info;
	sockaddr_in6 sa;
	int32_t res;

	std::memset(&info, 0x00, sizeof(info));
	std::memset(&sa, 0x00, sizeof(sa));
	sa.sin6_family = AF_INET6;

#if defined(CEX_OS_WINDOWS)

	addrinfo* result;
	addrinfo hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	result = NULL;

	// resolve the server address and port
	res = getaddrinfo(Host.c_str(), Service.c_str(), &hints, &result);

	if (res == 0)
	{
		addrinfo *p;
		void *addr;
		char ipstr[INET6_ADDRSTRLEN] = { 0 };
		std::string sai;

		for (p = result; p != NULL; p = p->ai_next)
		{
			if (p->ai_family == AF_INET6)
			{
				struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
				addr = &(ipv6->sin6_addr);
				inet_ntop(p->ai_family, addr, reinterpret_cast<PSTR>(ipstr), sizeof(ipstr));
				break;
			}
		}

		sai.assign(ipstr);
		ipv6_address ipa = ipv6_address::FromString(sai);
		info.address = ipa;
		info.port = static_cast<uint16_t>(ntohs(sa.sin6_port));

		if (result != NULL)
		{
			freeaddrinfo(result);
		}
	}

#else

	hostent* lphost;

	sa.sin6_len = sizeof(sa);
	sa.sin6_addr.s6_addr = inet_addr(Host.c_str());
	lphost = gethostbyname2(Host.c_str(), AF_INET6);
	res = lphost != NULL ? 0 : SOCKET_EINVAL;

	if (res == 0)
	{
		sa.sin6_addr.s6_addr = reinterpret_cast<in6_addr*>(lphost->h_addr)->s6_addr;
		ipv6_address ipa(reinterpret_cast<uint8_t*>(sa.sin6_addr));
		info.address = ipa;
		info.port = sa.sin6_port;
	}

#endif

	return info;
}

std::vector<std::string> NetworkTools::GetIpAddressList()
{
	std::vector<std::string> iplist;
	std::string tmpip;

#if defined(CEX_WINDOWS_SOCKETS)

	INT retv;
	struct addrinfo* address;
	struct addrinfo* addptr;
	struct addrinfo hints;

	address = NULL;
	addptr = NULL;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	retv = getaddrinfo("", "", &hints, &address);

	if (retv == 0)
	{
		// Retrieve each address and print out the hex bytes
		for (addptr = address; addptr != NULL; addptr = addptr->ai_next)
		{
			if (addptr->ai_family == AF_INET)
			{
				char buf[INET_ADDRSTRLEN];
				struct sockaddr_in* sockipv4;

				sockipv4 = reinterpret_cast<struct sockaddr_in*>(addptr->ai_addr);
				inet_ntop(AF_INET, &sockipv4->sin_addr, buf, INET_ADDRSTRLEN);
				tmpip.assign(buf, sizeof(buf));
				tmpip.erase(std::find(tmpip.begin(), tmpip.end(), '\0'), tmpip.end());
				iplist.push_back(tmpip);
			}
			else if (addptr->ai_family == AF_INET6)
			{
				LPSOCKADDR sockipv6;
				WCHAR ipv6buf[46];
				DWORD ipv6buflen;
				std::wstring tmpw;

				sockipv6 = reinterpret_cast<LPSOCKADDR>(addptr->ai_addr);
				ipv6buflen = 46;
				retv = WSAAddressToStringW(sockipv6, static_cast<DWORD>(addptr->ai_addrlen), NULL, ipv6buf, &ipv6buflen);
				tmpw.assign(ipv6buf, ipv6buflen);
				tmpip.assign(tmpw.begin(), tmpw.end());
				iplist.push_back(tmpip);
			}
			else
			{
				// not implemented
			}
		}
	}

#else
	struct ifaddrs* ifadds = NULL;
	struct ifaddrs* ifa = NULL;
	void* paddr = NULL;

	getifaddrs(&ifadds);

	for (ifa = ifadds; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
		{
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			// check it is IP4 is a valid IP4 Address
			paddr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			char addbuf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, paddr, addbuf, INET_ADDRSTRLEN);
			tmpip.assign(addbuf, INET_ADDRSTRLEN);
			iplist.push_back(tmpip);
			//printf("%s IP Address %s\n", ifa->ifa_name, addbuf);
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6)
		{
			// check it is IP6 is a valid IP6 Address
			paddr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
			char addbuf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, paddr, addbuf, INET6_ADDRSTRLEN);
			tmpip.assign(addbuf, INET6_ADDRSTRLEN);
			iplist.push_back(tmpip);
			//printf("%s IP Address %s\n", ifa->ifa_name, addbuf);
		}
	}

	if (ifadds != NULL)
	{
		freeifaddrs(ifadds);
	}
#endif

	return iplist;
}

std::string NetworkTools::GetPeerName(Socket &Source)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	sockaddr psa;
	socklen_t psalen;
	std::string name("");
	size_t slen;
	int32_t res;

	psalen = 0;

	res = getpeername(Source.Connection, &psa, &psalen);

	if (res == SOCKET_RET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("GetPeerName"), std::string("The socket address is invalid!"), ErrorCodes::SocketFailure);
	}

	slen = static_cast<size_t>(psalen);

	if (slen != 0)
	{
		name = reinterpret_cast<char*>(psa.sa_data);
	}

	return name;
}

std::string NetworkTools::GetSocketName(Socket &Source)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	sockaddr psa;
	socklen_t psalen;
	std::string name;
	size_t slen;
	int32_t res;

	psalen = 0;

	res = getsockname(Source.Connection, &psa, &psalen);

	if (res == SOCKET_RET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("GetSocketName"), std::string("The socket address is invalid!"), ErrorCodes::SocketFailure);
	}

	slen = static_cast<size_t>(psalen);

	if (slen != 0)
	{
		name = reinterpret_cast<char*>(psa.sa_data);
	}

	return name;
}

uint16_t NetworkTools::PortNameToNumber(const std::string &Name, const std::string &Protocol)
{
	CEXASSERT(Name.size() != 0, "the name parameter is invalid");
	CEXASSERT(Protocol.size() != 0, "the protocol parameter is invalid");

	servent* se;
	uint16_t port;

	port = static_cast<uint16_t>(atoi(Name.c_str()));

	if (IntegerTools::ToString(port) != Name)
	{
		se = getservbyname(Name.c_str(), Protocol.c_str());

		if (se == nullptr)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("PortNameToNumber"), std::string("The socket failed to identify the port name!"), ErrorCodes::SocketFailure);
		}

		port = static_cast<uint16_t>(ntohs(se->s_port));
	}

	return port;
}

NAMESPACE_TOOLSEND