#include "Socket.h"
#include "IntegerTools.h"
#include "inaddr.h"
#include <assert.h>

NAMESPACE_NETWORK

using Utility::IntegerTools;

//~~~Socket Class~~~//

Socket::Socket()
	:
	m_socket(),
	m_owner(false)
{
#if defined(CEX_WINDOWS_SOCKETS)
	StartSockets();
#endif
}

Socket::Socket(socket_t Socket, bool Owner)
	:
	m_socket(Socket),
	m_owner(Owner)
{
#if defined(CEX_WINDOWS_SOCKETS)
	StartSockets();
#endif
}

Socket::Socket(const Socket& Socket)
	:
	m_socket(Socket.m_socket),
	m_owner(false)
{
#if defined(CEX_WINDOWS_SOCKETS)
	StartSockets();
#endif
}

Socket::~Socket()
{
	if (m_socket != SOCKET_ERROR && m_socket != SOCKET_EINVAL)
	{
		CloseSocket();
		m_socket = NULL;
	}

	m_owner = false;

#if defined(CEX_WINDOWS_SOCKETS)
	ShutDownSockets();
#endif
}

//~~~Public Functions~~~//

bool Socket::Accept(Socket& Target, sockaddr* Psa, socklen_t* PsaLength)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	socket_t skt;
	bool ret;

	skt = accept(m_socket, Psa, PsaLength);

	if (skt == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("Accept"), std::string("The connection could not be established!"), ErrorCodes::Disconnected);
	}

	ret = (skt != INVALID_SOCKET && GetLastError() != SOCKET_EWOULDBLOCK);
	Target.AttachSocket(skt, true);
	SocketChanged(ret);

	return ret;
}

void Socket::AttachSocket(socket_t& Socket, bool Owner)
{
	if (Owner)
	{
		CloseSocket();
	}

	m_socket = Socket;
	m_owner = Owner;
}

//#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

void Socket::Bind(ushort Port, std::string& Address)
{
	/*sockaddr_in sadd;
	uint res;

	std::memset(&sadd, 0, sizeof(sadd));
	sadd.sin_family = AF_INET;

	if (Address.size() == 0)
	{
		sadd.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		res = inet_addr(Address.c_str());

		if (res == INADDR_NONE)
		{
			SetLastError(SOCKET_EINVAL);
			throw CryptoSocketException(std::string("Socket"), std::string("Bind"), std::string("The ip address is invalid!"), ErrorCodes::InvalidAddress);
		}

		sadd.sin_addr.s_addr = res;
	}

	sadd.sin_port = htons(static_cast<u_short>(Port));
	Bind(reinterpret_cast<sockaddr*>(&sadd), sizeof(sadd));*/
}

void Socket::Bind(const sockaddr* Psa, socklen_t PsaLength)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	// cygwin workaround: needs const_cast
	res = bind(m_socket, const_cast<sockaddr*>(Psa), PsaLength);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("Bind"), std::string("The connection binding has failed!"), ErrorCodes::InvalidSocket);
	}

	SocketChanged(res);
}

void Socket::Create(SocketAddressFamilyTypes SocketType)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	m_socket = socket(AF_INET, static_cast<int>(SocketType), 0x00000000L);

	if (m_socket == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Create"), std::string("The socket could not be created!"), ErrorCodes::InvalidState);
	}

	SocketChanged(0x00000000L);

	m_owner = true;
}

void Socket::CloseSocket()
{
	int res;

	if (m_socket != INVALID_SOCKET)
	{
#if defined(CEX_WINDOWS_SOCKETS)
		CancelIo(reinterpret_cast<HANDLE>(m_socket));
		res = closesocket(m_socket);

		if (res == SOCKET_ERROR)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket could not be closed!"), ErrorCodes::SocketFailure);
		}
#else
		res = close(m_socket);

		if (res == SOCKET_ERROR)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket could not be closed!"), ErrorCodes::SocketFailure);
		}
#endif

		m_socket = INVALID_SOCKET;
		SocketChanged(res);
	}
}

bool Socket::Connect(std::string& Address, ushort Port)
{
	/*CEXASSERT(Address.size() != 0, "the IP address is invalid.");

	sockaddr_in sa;
	hostent* lphost;

	std::memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(Address.c_str());

	if (sa.sin_addr.s_addr == INADDR_NONE)
	{
		//lphost = gethostbyname(Address.c_str());

		if (lphost == NULL)
		{
			SetLastError(SOCKET_EINVAL);
			throw CryptoSocketException(std::string("Socket"), std::string("Connect"), std::string("The destination host was not found!"), ErrorCodes::NotFound);
		}

		sa.sin_addr.s_addr = (reinterpret_cast<in_addr*>(lphost->h_addr))->s_addr;
	}

	sa.sin_port = htons(static_cast<u_short>(Port));

	return Connect(reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));*/
	return false;
}

bool Socket::Connect(const sockaddr* Psa, socklen_t PsaLength)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;
	bool ret;

	res = connect(m_socket, const_cast<sockaddr*>(Psa), PsaLength);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("Connect"), std::string("The connection could not be established!"), ErrorCodes::Disconnected);
	}

	ret = (res != SOCKET_ERROR && GetLastError() != SOCKET_EWOULDBLOCK);

	SocketChanged(ret);

	return ret;
}

socket_t Socket::DetachSocket()
{
	socket_t skt;

	skt = m_socket;
	m_socket = INVALID_SOCKET;
	SocketChanged(skt);

	return skt;
}

void Socket::GetPeerName(sockaddr* Psa, socklen_t* SaLength)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = getpeername(m_socket, Psa, SaLength);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("GetPeerName"), std::string("The peer could not be found!"), ErrorCodes::NotFound);
	}
}

void Socket::GetSocketName(sockaddr* Psa, socklen_t* PsaLength)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = getsockname(m_socket, Psa, PsaLength);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("GetSockName"), std::string("The host could not be found!"), ErrorCodes::NotFound);
	}
}

void Socket::IOCtl(long Command, unsigned long* Arguments)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

#if defined(CEX_WINDOWS_SOCKETS)
	res = ioctlsocket(m_socket, Command, Arguments);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("IOCtl"), std::string("The command was refused or unrecognized!"), ErrorCodes::IllegalOperation);
	}

	SocketChanged(res);
#else
	res = ioctl(m_socket, Command, Arguments);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("IOCtl"), std::string("The command was refused or unrecognized!"), ErrorCodes::IllegalOperation);
	}

	SocketChanged(res);
#endif
}

void Socket::Listen(int BackLog)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = listen(m_socket, BackLog);

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("Listen"), std::string("The socket did not enter the listening state!"), ErrorCodes::Disconnected);
	}

	SocketChanged(res);
}

ushort Socket::PortNameToNumber(const std::string& Name, const std::string& Protocol)
{
	servent* se;
	ushort port;

	port = static_cast<ushort>(atoi(Name.c_str()));

	if (IntegerTools::ToString(port) != Name)
	{
		se = getservbyname(Name.c_str(), Protocol.c_str());

		if (!se)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("PortNameToNumber"), std::string("The port number could not be parsed!"), ErrorCodes::InvalidAddress);
		}

		port = static_cast<ushort>(ntohs(se->s_port));
	}

	return port;
}

uint Socket::Receive(std::vector<byte>& Output, SocketRecieveFlags Flags)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = recv(m_socket, reinterpret_cast<char*>(Output.data()), IntegerTools::Min(static_cast<size_t>(INT_MAX), Output.size()), static_cast<int>(Flags));

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("Receive"), std::string("The socket received an error!"), ErrorCodes::BadRead);
	}

	SocketChanged(res);

	return res;
}

bool Socket::ReceiveReady(const timeval* Timeout)
{
	fd_set fds;
	timeval tcopy;
	int ready;

	FD_ZERO(&fds);
	FD_SET(m_socket, &fds);

	if (Timeout == NULL)
	{
		ready = select((int)m_socket + 1, &fds, NULL, NULL, NULL);
	}
	else
	{
		// select() modified timeout on Linux
		tcopy = *Timeout;
		ready = select((int)m_socket + 1, &fds, NULL, NULL, &tcopy);
	}

	if (ready == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("ReceiveReady"), std::string("The socket is not ready to receive data!"), ErrorCodes::Unreachable);
	}

	return ready > 0;
}

uint Socket::Send(const std::vector<byte>& Input, size_t Length, SocketSendFlags Flags)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = send(m_socket, reinterpret_cast<const char*>(Input.data()), IntegerTools::Min(static_cast<size_t>(INT_MAX), Length), static_cast<int>(Flags));

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("ReceiveReady"), std::string("The socket could not send data!"), ErrorCodes::Unreachable);
	}

	SocketChanged(res);

	return res;
}

bool Socket::SendReady(const timeval* Timeout)
{
	fd_set fds;
	timeval tcopy;
	int ready;

	FD_ZERO(&fds);
	FD_SET(m_socket, &fds);

	if (Timeout == NULL)
	{
		ready = select((int)m_socket + 1, NULL, &fds, NULL, NULL);
	}
	else
	{
		tcopy = *Timeout;
		ready = select((int)m_socket + 1, NULL, &fds, NULL, &tcopy);
	}

	if (ready == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("SendReady"), std::string("The socket is not ready to send data!"), ErrorCodes::SocketFailure);
	}

	return ready > 0;
}

void Socket::ShutDown(SocketShutdownFlags Parameters)
{
	CEXASSERT(m_socket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = shutdown(m_socket, static_cast<int>(Parameters));

	if (res == SOCKET_ERROR)
	{
		SetLastError(SOCKET_EINVAL);
		throw CryptoSocketException(std::string("Socket"), std::string("ShutDown"), std::string("The socket shutdown produced an error!"), ErrorCodes::SocketFailure);
	}

	SocketChanged(res);
}

//~~~Private Functions~~//

void Socket::ShutDownSockets()
{
#if defined(CEX_WINDOWS_SOCKETS)
	int res;

	res = WSACleanup();

	if (res != 0)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("ShutdownSockets"), std::string("The socket shutdown produced an error!"), ErrorCodes::SocketFailure);
	}

	SocketChanged(res);
#endif
}

void Socket::StartSockets()
{
#if defined(CEX_WINDOWS_SOCKETS)
	WSADATA wsd;
	int res;

	res = WSAStartup(0x0202, &wsd);

	if (res != 0)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("StartSockets"), std::string("The socket shutdown produced an error!"), ErrorCodes::SocketFailure);
	}

	SocketChanged(res);
#endif
}

int Socket::GetLastError()
{
#if defined(CEX_WINDOWS_SOCKETS)
	return WSAGetLastError();
#else
	return errno;
#endif
}

void Socket::SetLastError(int ErrorCode)
{
#if defined(CEX_WINDOWS_SOCKETS)
	WSASetLastError(ErrorCode);
#else
	errno = errorCode;
#endif
}

//~~~SocketListener Class~~~//


#if !defined (CEX_WINDOWS_SOCKETS)

/*SocketReceiver::SocketReceiver(Socket &s)
	: m_s(s), m_resultPending(false), m_eofReceived(false)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	//m_s.CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

SocketReceiver::~SocketReceiver()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	CancelIo((HANDLE)m_s.GetSocket());
#endif
}

bool SocketReceiver::Receive(byte* buf, size_t bufLen)
{
	assert(!m_resultPending && !m_eofReceived);

	DWORD flags = 0;
	// don't queue too much at once, or we might use up non-paged memory
	WSABUF wsabuf = { IntegerTools::Min((size_t)128 * 1024, bufLen), (char *)buf };
	if (WSARecv(m_s, &wsabuf, 1, &m_lastResult, &flags, &m_overlapped, NULL) == 0)
	{
		if (m_lastResult == 0)
			m_eofReceived = true;
	}
	else
	{
		switch (WSAGetLastError())
		{
		default:
			//m_s.CheckAndHandleError_int("WSARecv", SOCKET_ERROR);
		case WSAEDISCON:
			m_lastResult = 0;
			m_eofReceived = true;
			break;
		case WSA_IO_PENDING:
			m_resultPending = true;
		}
	}
	return !m_resultPending;
}

void SocketReceiver::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	if (m_resultPending)
		container.AddHandle(m_event, CallStack("SocketReceiver::GetWaitObjects() - result pending", &callStack));
	else if (!m_eofReceived)
		container.SetNoWait(CallStack("SocketReceiver::GetWaitObjects() - result ready", &callStack));
}

unsigned int SocketReceiver::GetReceiveResult()
{
	if (m_resultPending)
	{
		DWORD flags = 0;
		if (WSAGetOverlappedResult(m_s, &m_overlapped, &m_lastResult, false, &flags))
		{
			if (m_lastResult == 0)
				m_eofReceived = true;
		}
		else
		{
			switch (WSAGetLastError())
			{
			default:
				//m_s.CheckAndHandleError("WSAGetOverlappedResult", FALSE);
			case WSAEDISCON:
				m_lastResult = 0;
				m_eofReceived = true;
			}
		}
		m_resultPending = false;
	}
	return m_lastResult;
}*/

SocketSender::SocketSender(Socket &s)
	: m_s(s), m_resultPending(false), m_lastResult(0)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	//m_s.CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}


SocketSender::~SocketSender()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	CancelIo((HANDLE)m_s.GetSocket());
#endif
}

void SocketSender::Send(const byte* buf, size_t bufLen)
{
	assert(!m_resultPending);
	DWORD written = 0;
	// don't queue too much at once, or we might use up non-paged memory
	WSABUF wsabuf = { IntegerTools::Min((size_t)128 * 1024, bufLen), (char *)buf };
	if (WSASend(m_s, &wsabuf, 1, &written, 0, &m_overlapped, NULL) == 0)
	{
		m_resultPending = false;
		m_lastResult = written;
	}
	else
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			//m_s.CheckAndHandleError_int("WSASend", SOCKET_ERROR);
		}

		m_resultPending = true;
	}
}

void SocketSender::SendEof()
{
	assert(!m_resultPending);
	m_s.ShutDown(SD_SEND);
	//m_s.CheckAndHandleError("ResetEvent", ResetEvent(m_event));
	//m_s.CheckAndHandleError_int("WSAEventSelect", WSAEventSelect(m_s, m_event, FD_CLOSE));
	m_resultPending = true;
}

bool SocketSender::EofSent()
{
	if (m_resultPending)
	{
		WSANETWORKEVENTS events;
		//m_s.CheckAndHandleError_int("WSAEnumNetworkEvents", WSAEnumNetworkEvents(m_s, m_event, &events));
		if ((events.lNetworkEvents & FD_CLOSE) != FD_CLOSE)
			throw Socket::Err(m_s, "WSAEnumNetworkEvents (FD_CLOSE not present)", E_FAIL);
		if (events.iErrorCode[FD_CLOSE_BIT] != 0)
			throw Socket::Err(m_s, "FD_CLOSE (via WSAEnumNetworkEvents)", events.iErrorCode[FD_CLOSE_BIT]);
		m_resultPending = false;
	}
	return m_lastResult != 0;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	if (m_resultPending)
		container.AddHandle(m_event, CallStack("SocketSender::GetWaitObjects() - result pending", &callStack));
	else
		container.SetNoWait(CallStack("SocketSender::GetWaitObjects() - result ready", &callStack));
}

unsigned int SocketSender::GetSendResult()
{
	if (m_resultPending)
	{
		DWORD flags = 0;
		BOOL result = WSAGetOverlappedResult(m_s, &m_overlapped, &m_lastResult, false, &flags);
		//m_s.CheckAndHandleError("WSAGetOverlappedResult", result);
		m_resultPending = false;
	}
	return m_lastResult;
}

#endif

#if defined(CEX_BERKELEY_SOCKETS)

SocketReceiver::SocketReceiver(Socket &s)
	: m_s(s), m_lastResult(0), m_eofReceived(false)
{
}

void SocketReceiver::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	if (!m_eofReceived)
		container.AddReadFd(m_s, CallStack("SocketReceiver::GetWaitObjects()", &callStack));
}

bool SocketReceiver::Receive(byte* buf, size_t bufLen)
{
	m_lastResult = m_s.Receive(buf, bufLen);
	if (bufLen > 0 && m_lastResult == 0)
		m_eofReceived = true;
	return true;
}

unsigned int SocketReceiver::GetReceiveResult()
{
	return m_lastResult;
}

SocketSender::SocketSender(Socket &s)
	: m_s(s), m_lastResult(0)
{
}

void SocketSender::Send(const byte* buf, size_t bufLen)
{
	m_lastResult = m_s.Send(buf, bufLen);
}

void SocketSender::SendEof()
{
	m_s.ShutDown(SD_SEND);
}

unsigned int SocketSender::GetSendResult()
{
	return m_lastResult;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	container.AddWriteFd(m_s, CallStack("SocketSender::GetWaitObjects()", &callStack));
}

#endif

NAMESPACE_NETWORKEND
