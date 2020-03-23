#include "Socket.h"
#include "IntegerTools.h"
#include <assert.h>

NAMESPACE_NETWORK

/*
* TODO:
* Flesh out socket ErrorCodes enum and SetError constants and apply them
* Can enums be hard coded or not (do they align to standard values in *nix/Win?)
* Move more to .cpp file, and verify all includes are necessary
* Can and should reverences be used over pointers with Psa?
* Add the Message wait class
* Add server and client classes
* Network sink? QOS? Compression? What else is required?
* Write tests for every function
* Test on *nix..
*/

using Utility::IntegerTools;

#if !defined(INADDR_NONE)
#	define INADDR_NONE 0xFFFFFFFF* 
#endif

#if defined(CEX_WINDOWS_SOCKETS)
	const int SOCKET_EINVAL = WSAEINVAL;
	const int SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
#else
	const socket_t INVALID_SOCKET = -1;
	const int SD_RECEIVE = 0;
	const int SD_SEND = 1;
	const int SD_BOTH = 2;
	const int SOCKET_ERROR = -1;
	const int SOCKET_EINVAL = EINVAL;
	const int SOCKET_EWOULDBLOCK = EWOULDBLOCK;
#endif

//~~~Socket Class~~~//

Socket::Socket()
	:
	m_isOwner(true),
	m_rawSocket(INVALID_SOCKET)
{
#if defined(CEX_WINDOWS_SOCKETS)
	StartSockets();
#endif
}

Socket::Socket(socket_t &Socket, bool IsOwner)
	:
	m_isOwner(IsOwner),
	m_rawSocket(Socket)
{
#if defined(CEX_WINDOWS_SOCKETS)
	StartSockets();
#endif
}

Socket::~Socket()
{
	if (m_rawSocket != SOCKET_ERROR && m_rawSocket != SOCKET_EINVAL)
	{
		CloseSocket();
		m_rawSocket = NULL;
	}

	m_isOwner = false;

#if defined(CEX_WINDOWS_SOCKETS)
	ShutDownSockets();
#endif
}

//~~~Public Functions~~~//

bool Socket::Accept(Socket &Target, sockaddr* Psa, socklen_t* PsaLength)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");
	CEXASSERT(Psa != nullptr, "the socket address has not been initialized.");
	CEXASSERT(PsaLength != nullptr, "the socket address length has not been initialized.");

	socket_t skt;
	bool ret;

	skt = accept(m_rawSocket, Psa, PsaLength);
	ret = (skt != INVALID_SOCKET && skt != SOCKET_ERROR);

	if (!ret)
	{
		closesocket(skt);
		SetLastError(SOCKET_EINVAL);

		throw CryptoSocketException(std::string("Socket"), std::string("Accept"), std::string("The underlying sockets library would not accept the connection!"), ErrorCodes::SocketFailure);
	}

	Target.AttachSocket(skt, true);

	return ret;
}

void Socket::AttachSocket(socket_t &Socket, bool IsOwner)
{
	if (IsOwner)
	{
		CloseSocket();
	}

	m_rawSocket = Socket;
	m_isOwner = IsOwner;
}

void Socket::Bind(ushort Port, const std::string &Address, SocketAddressFamilies AddressFamily)
{
	sockaddr_in sadd;
	uint res;

	std::memset(&sadd, 0, sizeof(sadd));
	sadd.sin_family = static_cast<int>(AddressFamily);

	if (Address.size() == 0)
	{
		sadd.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
#if defined(CEX_WINDOWS_SOCKETS)
		struct sockaddr_in sa;
		res = inet_pton(AF_INET, Address.c_str(), &(sa.sin_addr));
#else
		res = inet_addr(addr);
#endif
		if (res != INADDR_NONE)
		{
			sadd.sin_addr.s_addr = res;
		}
		else
		{
			SetLastError(SOCKET_EINVAL);
			throw CryptoSocketException(std::string("Socket"), std::string("Bind"), std::string("The underlying sockets library would not accept the binding!"), ErrorCodes::SocketFailure);
		}
	}

	sadd.sin_port = htons(static_cast<ushort>(Port));
	Bind(reinterpret_cast<sockaddr*>(&sadd), sizeof(sadd));
}

void Socket::Bind(const sockaddr* Psa, socklen_t PsaLength)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = bind(m_rawSocket, const_cast<sockaddr*>(Psa), PsaLength);

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Bind"), std::string("The underlying sockets library would not accept the binding!"), ErrorCodes::SocketFailure);
	}
}

void Socket::CloseSocket()
{
	int res;

	if (m_rawSocket != INVALID_SOCKET)
	{
#if defined(CEX_WINDOWS_SOCKETS)
		res = shutdown(m_rawSocket, SD_SEND);

		if (res != SOCKET_ERROR)
		{
			closesocket(m_rawSocket);
		}
		else
		{
			SetLastError(SOCKET_EINVAL);
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket closed abnormally!"), ErrorCodes::SocketFailure);
		}

		m_rawSocket = INVALID_SOCKET;

#else
		res = close(m_rawSocket);

		if (res == SOCKET_ERROR)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("CloseSocket"), std::string("The socket closed abnormally!"), ErrorCodes::SocketFailure);
		}
#endif
	}
}

void Socket::Create(SocketAddressFamilies FamilyType, SocketTypes SocketType, SocketProtocols ProtocolType)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	m_rawSocket = socket(static_cast<int>(FamilyType), static_cast<int>(SocketType), static_cast<int>(ProtocolType));

	if (m_rawSocket != SOCKET_ERROR)
	{
		m_isOwner = true;
	}
	else
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Create"), std::string("The socket could not be created!"), ErrorCodes::SocketFailure);
	}
}

bool Socket::Connect(std::string &Address, ushort Port, SocketAddressFamilies AddressFamily)
{
	CEXASSERT(Address.size() != 0, "the IP address is invalid.");

	sockaddr_in sa;
	int res;
	bool ret;

	res = 0;
	ret = false;
	std::memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;

#if defined(CEX_WINDOWS_SOCKETS)
	inet_pton(AF_INET, Address.c_str(), &(sa.sin_addr));
#else
	sa.sin_addr.s_addr = inet_addr(Address.c_str());
#endif

	if (sa.sin_addr.s_addr == INADDR_NONE)
	{
#if defined(CEX_WINDOWS_SOCKETS)
		std::string pport = IntegerTools::ToString(Port);
		addrinfo *result = NULL;
		addrinfo hints;
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = static_cast<int>(AddressFamily);
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// resolve the server address and port
		res = getaddrinfo(Address.c_str(), pport.c_str(), &hints, &result);

		if (res == 0)
		{
			sa.sin_addr.s_addr = (reinterpret_cast<in_addr*>(result->ai_addr))->s_addr;
			freeaddrinfo(result);
		}
#else
		hostent* lphost;
		sa.sin_addr.s_addr = inet_addr(Address.c_str());
		lphost = gethostbyname(Address.c_str());

		if (lphost != NULL)
		{
			sa.sin_addr.s_addr = (reinterpret_cast<in_addr*>(lphost->h_addr))->s_addr;
		}
		else
		{
			res = SOCKET_EINVAL;
		}

#endif
	}

	if (res == 0)
	{
		sa.sin_port = htons(static_cast<u_short>(Port));
		ret = Connect(reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
	}
	else
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Connect"), std::string("The socket could not be connected!"), ErrorCodes::SocketFailure);
	}

	return ret;
}

bool Socket::Connect(const sockaddr* Psa, socklen_t PsaLength)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");
	CEXASSERT(Psa != nullptr, "the socket address can not be null.");

	int res;

	res = connect(m_rawSocket, const_cast<sockaddr*>(Psa), PsaLength);

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Connect"), std::string("The socket could not be connected!"), ErrorCodes::SocketFailure);
	}

	return (GetLastError() != SOCKET_EWOULDBLOCK);
}

socket_t Socket::DetachSocket()
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	socket_t skt;

	skt = m_rawSocket;
	m_rawSocket = INVALID_SOCKET;

	return skt;
}

void Socket::GetPeerName(sockaddr* Psa, socklen_t* SaLength)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = getpeername(m_rawSocket, Psa, SaLength);

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("GetPeerName"), std::string("The socket address is invalid!"), ErrorCodes::SocketFailure);
	}
}

void Socket::GetSocketName(sockaddr* Psa, socklen_t* PsaLength)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = getsockname(m_rawSocket, Psa, PsaLength);

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("GetSocketName"), std::string("The socket address is invalid!"), ErrorCodes::SocketFailure);
	}
}

void Socket::IOCtl(long Command, unsigned long* Arguments)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

#if defined(CEX_WINDOWS_SOCKETS)
	res = ioctlsocket(m_rawSocket, Command, Arguments);
#else
	res = ioctl(m_rawSocket, Command, Arguments);
#endif

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("IOCtl"), std::string("The command is invalid or refused!"), ErrorCodes::SocketFailure);
	}
}

void Socket::Listen(int BackLog)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = listen(m_rawSocket, BackLog);

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Listen"), std::string("The socket failed to enter the listening state!"), ErrorCodes::SocketFailure);
	}
}

ushort Socket::PortNameToNumber(const std::string &Name, const std::string &Protocol)
{
	CEXASSERT(Name.size() != 0, "the name parameter is invalid");
	CEXASSERT(Protocol.size() != 0, "the protocol parameter is invalid");

	servent* se;
	ushort port;

	port = static_cast<ushort>(atoi(Name.c_str()));

	if (IntegerTools::ToString(port) != Name)
	{
		se = getservbyname(Name.c_str(), Protocol.c_str());

		if (se == nullptr)
		{
			throw CryptoSocketException(std::string("Socket"), std::string("PortNameToNumber"), std::string("The socket failed to identify the port name!"), ErrorCodes::SocketFailure);
		}

		port = static_cast<ushort>(ntohs(se->s_port));
	}

	return port;
}

uint Socket::Receive(std::vector<byte> &Output, SocketRecieveFlags Flags)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");
	CEXASSERT(Output.size() != 0, "the output parameter is invalid");

	int res;

	res = recv(m_rawSocket, reinterpret_cast<char*>(Output.data()), Output.size(), static_cast<int>(Flags));

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Receive"), std::string("The socket receive function has failed!"), ErrorCodes::SocketFailure);
	}

	return static_cast<size_t>(res);
}

bool Socket::ReceiveReady(const timeval* Timeout)
{
	fd_set fds;
	timeval tcopy;
	int res;

	FD_ZERO(&fds);
	FD_SET(m_rawSocket, &fds);

	if (Timeout == nullptr)
	{
		res = select(static_cast<int>(m_rawSocket) + 1, &fds, nullptr, nullptr, nullptr);
	}
	else
	{
		// select() modified timeout on Linux
		tcopy = *Timeout;
		res = select(static_cast<int>(m_rawSocket) + 1, &fds, nullptr, nullptr, &tcopy);
	}

	return static_cast<bool>(res > 0);
}

uint Socket::Send(const std::vector<byte>& Input, size_t Length, SocketSendFlags Flags)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = send(m_rawSocket, reinterpret_cast<const char*>(Input.data()), Length, static_cast<int>(Flags));

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("Send"), std::string("The socket send function has failed!"), ErrorCodes::SocketFailure);
	}

	return res;
}

bool Socket::SendReady(const timeval* Timeout)
{
	fd_set fds;
	timeval tcopy;
	int res;

	FD_ZERO(&fds);
	FD_SET(m_rawSocket, &fds);

	if (Timeout == NULL)
	{
		res = select((int)m_rawSocket + 1, NULL, &fds, NULL, NULL);
	}
	else
	{
		tcopy = *Timeout;
		res = select((int)m_rawSocket + 1, NULL, &fds, NULL, &tcopy);
	}

	return static_cast<bool>(res > 0);
}

void Socket::ShutDown(SocketShutdownFlags Parameters)
{
	CEXASSERT(m_rawSocket != INVALID_SOCKET, "the socket has not been initialized.");

	int res;

	res = shutdown(m_rawSocket, static_cast<int>(Parameters));

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("ShutDown"), std::string("The socket shutdown function has errored!"), ErrorCodes::SocketFailure);
	}

	closesocket(m_rawSocket);
}

int Socket::GetLastError()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	return WSAGetLastError();
#else
	return errno;
#endif
}

void Socket::SetLastError(int ErrorCode)
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	WSASetLastError(errorCode);
#else
	errno = ErrorCode;
#endif
}

//~~~Private Functions~~//

void Socket::ShutDownSockets()
{
#if defined(CEX_WINDOWS_SOCKETS)
	int res;

	res = WSACleanup();

	if (res != 0)
	{
		throw CryptoSocketException(std::string("Socket"), std::string("ShutDownSockets"), std::string("The sockets library did not terminate correctly!"), ErrorCodes::InvalidState);
	}
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
		throw CryptoSocketException(std::string("Socket"), std::string("StartSockets"), std::string("The sockets library could not be started!"), ErrorCodes::SocketFailure);
	}
#endif
}

//~~~SocketListener Class~~~//

#if defined(CEX_WINDOWS_SOCKETS)

SocketReceiver::SocketReceiver(Socket &s)
	: 
	m_s(s), 
	m_resultPending(false), 
	m_eofReceived(false)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	//m_rawSocket.CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

SocketReceiver::~SocketReceiver()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	CancelIo((HANDLE)m_rawSocket.GetSocket());
#endif
}

bool SocketReceiver::Receive(byte* buf, size_t bufLen)
{
	assert(!m_resultPending && !m_eofReceived);

	DWORD flags = 0;
	// don't queue too much at once, or we might use up non-paged memory
	WSABUF wsabuf = 
	{ 
		IntegerTools::Min((size_t)128 * 1024, bufLen), (char*)buf 
	};

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
			//m_rawSocket.CheckAndHandleError_int("WSARecv", SOCKET_ERROR);
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
				//m_rawSocket.CheckAndHandleError("WSAGetOverlappedResult", FALSE);
			case WSAEDISCON:
				m_lastResult = 0;
				m_eofReceived = true;
			}
		}
		m_resultPending = false;
	}
	return m_lastResult;
}

SocketSender::SocketSender(Socket &s)
	: 
	m_s(s), 
	m_resultPending(false), 
	m_lastResult(0)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);
	//m_rawSocket.CheckAndHandleError("CreateEvent", m_event.HandleValid());
	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

SocketSender::~SocketSender()
{
#if defined(CEX_WINDOWS_SOCKETS)
	CancelIo((HANDLE)m_s.GetSocket());
#endif
}

void SocketSender::Send(const byte* buf, size_t bufLen)
{
	assert(!m_resultPending);
	DWORD written;

	written = 0;

	// don't queue too much at once, or we might use up non-paged memory
	WSABUF wsabuf = 
	{ 
		IntegerTools::Min((size_t)128 * 1024, bufLen), 
		(char*)buf 
	};

	if (WSASend(m_s, &wsabuf, 1, &written, 0, &m_overlapped, NULL) == 0)
	{
		m_resultPending = false;
		m_lastResult = written;
	}
	else
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			//m_rawSocket.CheckAndHandleError_int("WSASend", SOCKET_ERROR);
		}

		m_resultPending = true;
	}
}

void SocketSender::SendEof()
{
	assert(!m_resultPending);
	m_s.ShutDown(SocketShutdownFlags::Send);
	ResetEvent(m_event);
	WSAEventSelect(m_s, m_event, FD_CLOSE);
	m_resultPending = true;
}

bool SocketSender::EofSent()
{
	if (m_resultPending)
	{
		WSANETWORKEVENTS events;
		WSAEnumNetworkEvents(m_s, m_event, &events);

		if ((events.lNetworkEvents & FD_CLOSE) != FD_CLOSE)
		{
			throw;// Socket::Err(m_rawSocket, "WSAEnumNetworkEvents (FD_CLOSE not present)", E_FAIL);
		}

		if (events.iErrorCode[FD_CLOSE_BIT] != 0)
		{
			throw;// Socket::Err(m_rawSocket, "FD_CLOSE (via WSAEnumNetworkEvents)", events.iErrorCode[FD_CLOSE_BIT]);
		}

		m_resultPending = false;
	}
	return m_lastResult != 0;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	if (m_resultPending)
	{
		container.AddHandle(m_event, CallStack("SocketSender::GetWaitObjects() - result pending", &callStack));
	}
	else
	{
		container.SetNoWait(CallStack("SocketSender::GetWaitObjects() - result ready", &callStack));
	}
}

unsigned int SocketSender::GetSendResult()
{
	if (m_resultPending)
	{
		DWORD flags = 0;
		BOOL result = WSAGetOverlappedResult(m_s, &m_overlapped, &m_lastResult, false, &flags);
		//m_rawSocket.CheckAndHandleError("WSAGetOverlappedResult", result);
		m_resultPending = false;
	}

	return m_lastResult;
}

#endif

#if defined(CEX_BERKELEY_SOCKETS)

SocketReceiver::SocketReceiver(Socket &s)
	: m_rawSocket(s), m_lastResult(0), m_eofReceived(false)
{
}

void SocketReceiver::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	if (!m_eofReceived)
		container.AddReadFd(m_rawSocket, CallStack("SocketReceiver::GetWaitObjects()", &callStack));
}

bool SocketReceiver::Receive(byte* buf, size_t bufLen)
{
	m_lastResult = m_rawSocket.Receive(buf, bufLen);
	if (bufLen > 0 && m_lastResult == 0)
		m_eofReceived = true;
	return true;
}

unsigned int SocketReceiver::GetReceiveResult()
{
	return m_lastResult;
}

SocketSender::SocketSender(Socket &s)
	: m_rawSocket(s), m_lastResult(0)
{
}

void SocketSender::Send(const byte* buf, size_t bufLen)
{
	m_lastResult = m_rawSocket.Send(buf, bufLen);
}

void SocketSender::SendEof()
{
	m_rawSocket.ShutDown(SD_SEND);
}

unsigned int SocketSender::GetSendResult()
{
	return m_lastResult;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack)
{
	container.AddWriteFd(m_rawSocket, CallStack("SocketSender::GetWaitObjects()", &callStack));
}

#endif

NAMESPACE_NETWORKEND
// ***server code***
/*
#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int __cdecl main(void)
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// No longer need server socket
	closesocket(ListenSocket);

	// Receive until the peer shuts down the connection
	do {

		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);

			// Echo the buffer back to the sender
			iSendResult = send(ClientSocket, recvbuf, iResult, 0);
			if (iSendResult == SOCKET_ERROR) {
				printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}
			printf("Bytes sent: %d\n", iSendResult);
		}
		else if (iResult == 0)
			printf("Connection closing...\n");
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();

	return 0;
}
*/

// ***client code***
/*
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	const char *sendbuf = "this is a test";
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;

	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		return 1;
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Send an initial buffer
	iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	printf("Bytes Sent: %ld\n", iResult);

	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// Receive until the peer closes the connection
	do {

		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0)
			printf("Bytes received: %d\n", iResult);
		else if (iResult == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());

	} while (iResult > 0);

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}
*/