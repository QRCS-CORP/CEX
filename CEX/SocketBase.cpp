#include "SocketBase.h"

NAMESPACE_NETWORK

#if defined(CEX_OS_WINDOWS)
	const int SOCKET_EINVAL = WSAEINVAL;
	const int SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
#else
	const int SD_RECEIVE = 0x00000000L;
	const int SD_SEND = 0x00000001L;
	const int SD_BOTH = 0x00000002L;
	const int SOCKET_EINVAL = EINVAL;
	const int SOCKET_EWOULDBLOCK = EWOULDBLOCK;
#endif

//~~~Accessors~~~//

bool SocketBase::IsBlocking(Socket &Source)
{
	char b[1];
	bool ret;

	ret = (recv(Source.Connection, b, 0, 0) == SOCKET_RET_SUCCESS);

	return ret;
}

bool SocketBase::IsConnected(Socket &Source)
{
	int err;
	char buf;
	bool ret;

	ret = true;

	err = recv(Source.Connection, &buf, 1, MSG_PEEK);

	if (err == SOCKET_RET_ERROR)
	{
		if (GetLastError() != SocketExceptions::SocketWouldBlock)
		{
			ret = false;
		}
	}

	return ret;
}

//~~~Public Functions~~~//

bool SocketBase::Accept(Socket &Source, Socket &Target)
{
	bool ret;

	if (Source.AddressFamily == SocketAddressFamilies::IPv4)
	{
		ret = Acceptv4(Source, Target);
	}
	else
	{
		ret = Acceptv6(Source, Target);
	}

	return ret;
}

void SocketBase::Attach(Socket &Source, Socket &Target)
{
	Source = Socket(Target);
}

bool SocketBase::Bind(Socket &Source, const ipv4_address &Address, ushort Port)
{
	sockaddr_in sa;
	int res;

	std::memset(&sa, 0x00, sizeof(sa));

#if defined(CEX_OS_POSIX)
	sa.sin_len = sizeof(sa);
#endif
	sa.sin_family = AF_INET;
	sa.sin_port = htons(static_cast<ushort>(Port));
	res = bind(Source.Connection, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
	Source.Address = Address.ToString(Address);
	Source.AddressFamily = SocketAddressFamilies::IPv4;

	return (res != SOCKET_RET_ERROR);
}

bool SocketBase::Bind(Socket &Source, const ipv6_address &Address, ushort Port)
{
	sockaddr_in6 sa;
	int res;

	std::memset(&sa, 0x00, sizeof(sa));

#if defined(CEX_OS_POSIX)
	sa.sin6_len = sizeof(sa);
#endif
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(static_cast<ushort>(Port));
	res = bind(Source.Connection, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
	Source.Address = Address.ToString(Address);
	Source.AddressFamily = SocketAddressFamilies::IPv6;

	return (res != SOCKET_RET_ERROR);
}

void SocketBase::CloseSocket(Socket &Source)
{
	int res;

	if (Source.Connection != UNINITIALIZED_SOCKET && Source.Connection != SOCKET_RET_ERROR)
	{
#if defined(CEX_OS_WINDOWS)
		res = shutdown(Source.Connection, SD_SEND);

		if (res != SOCKET_RET_ERROR)
		{
			closesocket(Source.Connection);
		}
		else
		{
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket closed abnormally!"), ErrorCodes::SocketFailure);
		}

#else
		res = close(Source.Connection);

		if (res == SOCKET_RET_ERROR)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket closed abnormally!"), ErrorCodes::SocketFailure);
		}
#endif
	}

	Source.Clear();
}

bool SocketBase::Connect(Socket &Source, const ipv4_address &Address, ushort Port)
{
	sockaddr_in sa;
	std::string sadd;
	int res;

	std::memset(&sa, 0x00, sizeof(sa));

#if defined(CEX_OS_POSIX)
	sa.sin_len = sizeof(sa);
#endif
	sa.sin_family = AF_INET;
	sa.sin_port = htons(Port);
	sadd = ipv4_address::ToString(Address);

#if defined(CEX_OS_WINDOWS)
	inet_pton(AF_INET, sadd.c_str(), &(sa.sin_addr));
#else
	sa.sin_addr.s_addr = inet_addr(sadd.c_str());
#endif

	res = connect(Source.Connection, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));

	if (res != SOCKET_RET_ERROR)
	{
		Source.Address = sadd;
		Source.AddressFamily = SocketAddressFamilies::IPv4;
		Source.ConnectionStatus = SocketStates::Connected;
	}

	return (res != SOCKET_RET_ERROR);
}

bool SocketBase::Connect(Socket &Source, const ipv6_address &Address, ushort Port)
{
	sockaddr_in6 sa;
	std::string sadd;
	int res;

	std::memset(&sa, 0x00, sizeof(sa));

#if defined(CEX_OS_POSIX)
	sa.sin6_len = sizeof(sa);
#endif
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(Port);
	sadd = ipv6_address::ToString(Address);

#if defined(CEX_OS_WINDOWS)
	inet_pton(AF_INET6, sadd.c_str(), &(sa.sin6_addr));
#else
	sa.sin6_addr.s_addr = inet_addr(sadd.c_str());
#endif

	res = connect(Source.Connection, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));

	if (res != SOCKET_RET_ERROR)
	{
		Source.Address = sadd;
		Source.AddressFamily = SocketAddressFamilies::IPv6;
		Source.ConnectionStatus = SocketStates::Connected;
	}

	return (res != SOCKET_RET_ERROR);
}

bool SocketBase::Create(Socket &Source)
{
	CEXASSERT(Source.Connection == UNINITIALIZED_SOCKET, "the socket has been initialized.");

	Source.Connection = socket(static_cast<int>(Source.AddressFamily), static_cast<int>(Source.SocketTransport), static_cast<int>(Source.SocketProtocol));

	return (Source.Connection != SOCKET_RET_ERROR);
}

bool SocketBase::Listen(Socket &Source, int BackLog)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	int res;

	res = listen(Source.Connection, BackLog);

	return (res != SOCKET_RET_ERROR);
}

uint SocketBase::Receive(Socket &Source, std::vector<byte> &Output, SocketReceiveFlags Flags)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");
	CEXASSERT(Output.size() != 0, "the output parameter is invalid");

	int res;

	res = recv(Source.Connection, reinterpret_cast<char*>(Output.data()), static_cast<int>(Output.size()), static_cast<int>(Flags));

	if (res == SOCKET_RET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Receive"), std::string("The socket receive function has failed!"), ErrorCodes::SocketFailure);
	}

	return static_cast<size_t>(res);
}

uint SocketBase::Send(Socket &Source, const std::vector<byte> &Input, size_t Length, SocketSendFlags Flags)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	int res;


	res = send(Source.Connection, reinterpret_cast<const char*>(Input.data()), static_cast<int>(Length) + 1, static_cast<int>(Flags));

	if (res == SOCKET_RET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Send"), std::string("The socket send function has failed!"), ErrorCodes::SocketFailure);
	}

	return res;
}

void SocketBase::ShutDown(Socket &Source, SocketShutdownFlags Parameters)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	int res;

	if (Source.Connection != UNINITIALIZED_SOCKET && IsConnected(Source))
	{
		res = shutdown(Source.Connection, static_cast<int>(Parameters));

		if (res == SOCKET_RET_ERROR)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("ShutDown"), std::string("The socket shutdown function has errored!"), ErrorCodes::SocketFailure);
		}
	}

#if defined(CEX_OS_WINDOWS)
	closesocket(Source.Connection);
#else
	close(Source.Connection);
#endif

	Source.Connection = UNINITIALIZED_SOCKET;
}

//~~~Helper Functions~~~//

SocketExceptions SocketBase::GetLastError()
{
#if defined(CEX_OS_WINDOWS)
	return static_cast<SocketExceptions>(WSAGetLastError());
#else
	return static_cast<SocketExceptions>(errno);
#endif
}

void SocketBase::IOCtl(Socket &Source, long Command, ulong* Arguments)
{
	CEXASSERT(Source.Connection != UNINITIALIZED_SOCKET, "the socket has not been initialized.");

	int res;

#if defined(CEX_OS_WINDOWS)
	res = ioctlsocket(Source.Connection, Command, reinterpret_cast<u_long*>(Arguments));
#else
	res = ioctl((int)Source, (int)Command, (char*)Arguments);
#endif

	if (res == SOCKET_RET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("IOCtl"), std::string("The command is invalid or refused!"), ErrorCodes::SocketFailure);
	}
}

bool SocketBase::ReceiveReady(Socket &Source, const timeval* Timeout)
{
	fd_set fds;
	const timeval* tcopy;
	int res;

	FD_ZERO(&fds);
	FD_SET(Source.Connection, &fds);

	if (Timeout == nullptr)
	{
		res = select(static_cast<int>(Source.Connection) + 1, &fds, nullptr, nullptr, nullptr);
	}
	else
	{
		// select() modified timeout on Linux
		tcopy = Timeout;
		res = select(static_cast<int>(Source.Connection) + 1, &fds, nullptr, nullptr, tcopy);
	}

	return static_cast<bool>(res > 0);
}

bool SocketBase::SendReady(Socket &Source, const timeval* Timeout)
{
	fd_set fds;
	const timeval* tcopy;
	int res;

	FD_ZERO(&fds);
	FD_SET(Source.Connection, &fds);

	if (Timeout == NULL)
	{
		res = select(static_cast<int>(Source.Connection) + 1, NULL, &fds, NULL, NULL);
	}
	else
	{
		tcopy = Timeout;
		res = select(static_cast<int>(Source.Connection) + 1, NULL, &fds, NULL, tcopy);
	}

	return static_cast<bool>(res > 0);
}

void SocketBase::SetLastError(int ErrorCode)
{
#if defined(CEX_OS_WINDOWS)
	WSASetLastError(ErrorCode);
#else
	errno = ErrorCode;
#endif
}

void SocketBase::ShutDownSockets()
{
#if defined(CEX_OS_WINDOWS)
	int res;

	res = WSACleanup();

	if (res != 0)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("ShutDownSockets"), std::string("The sockets library did not terminate correctly!"), ErrorCodes::InvalidState);
	}
#endif
}

void SocketBase::SocketOption(Socket &Source, SocketProtocols Protocol, SocketOptions TcpOptions)
{
#if defined(CEX_OS_WINDOWS)
	char code;
	code = static_cast<char>(Protocol);
#else
	int code;
	code = static_cast<int>(Protocol);
#endif

	setsockopt(Source.Connection, static_cast<int>(TcpOptions), static_cast<int>(Protocol), &code, sizeof(code));
}

void SocketBase::StartSockets()
{
#if defined(CEX_OS_WINDOWS)
	WSADATA wsd;
	int res;

	res = WSAStartup(0x0202, &wsd);

	if (res != 0)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("StartSockets"), std::string("The sockets library could not be started!"), ErrorCodes::SocketFailure);
	}
#endif
}

//~~~Private Functions~~~//

bool SocketBase::Acceptv4(Socket &Source, Socket &Target)
{
	Socket rskt;
	sockaddr_in sa;
	socklen_t salen;
	char astr[INET_ADDRSTRLEN];
	bool ret;

	salen = sizeof(sa);
	memset(&sa, 0x00, salen);
	rskt = Socket(Source);
	rskt.Connection = 0;
	rskt.ConnectionStatus = SocketStates::None;

#if defined(CEX_OS_POSIX)
	sa.sin_len = sizeof(sa);
#endif

	rskt.Connection = accept(Source.Connection, reinterpret_cast<sockaddr*>(&sa), &salen);
	ret = (rskt.Connection != UNINITIALIZED_SOCKET && rskt.Connection != SOCKET_RET_ERROR);

	if (ret == true)
	{
		Attach(Target, rskt);
		Target.ConnectionStatus = SocketStates::Connected;
		inet_ntop(AF_INET, &sa.sin_addr, astr, INET_ADDRSTRLEN);
		Target.Address = std::string(astr);
		Target.Port = static_cast<ushort>(ntohs(sa.sin_port));
	}
	else
	{
		CloseSocket(rskt);
	}

	return ret;
}

bool SocketBase::Acceptv6(Socket &Source, Socket &Target)
{
	Socket rskt;
	socklen_t salen;
	sockaddr_in6 sa;
	char astr[INET6_ADDRSTRLEN];
	bool ret;

	salen = sizeof(sa);
	memset(&sa, 0x00, salen);
	rskt = Socket(Source);
	rskt.Connection = 0;
	rskt.ConnectionStatus = SocketStates::None;

#if defined(CEX_OS_POSIX)
	sa.sin6_len = sizeof(sa);
#endif

	rskt.Connection = accept(Source.Connection, reinterpret_cast<sockaddr*>(&sa), &salen);
	ret = (rskt.Connection != UNINITIALIZED_SOCKET && rskt.Connection != SOCKET_RET_ERROR);

	if (ret == true)
	{
		Attach(Target, rskt);
		Target.ConnectionStatus = SocketStates::Connected;
		inet_ntop(AF_INET6, &sa.sin6_addr, astr, INET6_ADDRSTRLEN);
		Target.Address = std::string(astr);
		Target.Port = static_cast<ushort>(ntohs(sa.sin6_port));
	}
	else
	{
		CloseSocket(rskt);
	}

	return ret;
}

NAMESPACE_NETWORKEND