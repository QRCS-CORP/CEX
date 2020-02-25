#ifndef CEX_SOCKET_H
#define CEX_SOCKET_H

#include "CexDomain.h"
#include "CryptoSocketException.h"
#include "Wait.h"
#include "WindowsHandle.h"

#if defined(CEX_WINDOWS_SOCKETS)
#	include <winsock2.h>
#	include <ws2def.h>
#	include <WS2tcpip.h>
#	include <inaddr.h>
#	pragma comment(lib, "ws2_32.lib")
#else
#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <unistd.h>
#endif

NAMESPACE_NETWORK

using Exception::CryptoSocketException;
using Enumeration::ErrorCodes;
using Utility::WindowsHandle;

#if defined(CEX_WINDOWS_SOCKETS)
	typedef int socklen_t;
	typedef ::SOCKET socket_t;
#else
	typedef int socket_t;
#endif

/// <summary>
/// The socket address family type
/// </summary>
enum class SocketAddressFamilies : int
{
	/// <summary>
	/// No address family is specified
	/// </summary>
	None = AF_UNSPEC,
	/// <summary>
	/// Unix local to host (pipes, portals)
	/// </summary>
	UNIX = AF_UNIX,
	/// <summary>
	/// The Internet Protocol 4 address family
	/// </summary>
	IPv4 = AF_INET,
	/// <summary>
	/// The Internet Protocol 6 address family
	/// </summary>
	IPv6 = AF_INET6
};

/// <summary>
/// The socket transmission type
/// </summary>
enum class SocketTypes : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Streaming connection
	/// </summary>
	Stream = SOCK_STREAM,
	/// <summary>
	/// Datagram connection
	/// </summary>
	Datagram = SOCK_DGRAM,
	/// <summary>
	/// TCP Raw socket
	/// </summary>
	Raw = SOCK_RAW,
	/// <summary>
	/// Reliable protocol
	/// </summary>
	Reliable = SOCK_RDM,
	/// <summary>
	/// Sequenced packets
	/// </summary>
	Sequenced = SOCK_SEQPACKET
};

/// <summary>
/// The socket IP protocol type
/// </summary>
enum class SocketProtocols : int
{
	/// <summary>
	/// IPv6 Hop-by-Hop options
	/// </summary>
	IPv6HopOpts = IPPROTO_HOPOPTS,
	/// <summary>
	/// Internet Control Messaging Protocol
	/// </summary>
	ICMP = IPPROTO_ICMP,
	/// <summary>
	/// Internet Gateway Messaging Protocol
	/// </summary>
	IGMP = IPPROTO_IGMP,
	/// <summary>
	/// Internet Protocol version 4
	/// </summary>
	IPv4 = IPPROTO_IPV4,
	/// <summary>
	/// Transport Control Protocol
	/// </summary>
	TCP = IPPROTO_TCP,
	/// <summary>
	/// Exterior Gateway Protocol
	/// </summary>
	EGP = IPPROTO_EGP,
	/// <summary>
	/// Interior Gateway Protocol
	/// </summary>
	IGP = IPPROTO_IGP,
	/// <summary>
	/// Unreliable Delivery Protocol
	/// </summary>
	UDP = IPPROTO_UDP,
	/// <summary>
	/// IPSEC Discovery Protocol
	/// </summary>
	IDP = IPPROTO_IDP,
	/// <summary>
	/// Reliable Datagram Protocol
	/// </summary>
	RDP = IPPROTO_RDP,
	/// <summary>
	/// IPv6 header
	/// </summary>
	IPv6 = IPPROTO_IPV6,
	/// <summary>
	/// IPv6 Routing header
	/// </summary>
	IPv6Routing = IPPROTO_ROUTING,
	/// <summary>
	/// IPv6 fragmentation header
	/// </summary>
	IPv6Fragment = IPPROTO_FRAGMENT,
	/// <summary>
	/// Encapsulating security payload
	/// </summary>
	ESP = IPPROTO_ESP,
	/// <summary>
	/// IPv6 authentication header
	/// </summary>
	AH = IPPROTO_AH,
	/// <summary>
	/// ICMPv6
	/// </summary>
	ICMPv6 = IPPROTO_ICMPV6,
	/// <summary>
	/// IPv6 no next header
	/// </summary>
	IPv6NoHeader = IPPROTO_NONE,
	/// <summary>
	/// IPv6 Destination options
	/// </summary>
	DSTOPTS = IPPROTO_DSTOPTS,
	/// <summary>
	/// Neighbor Discovery?
	/// </summary>
	ND = IPPROTO_ND,
	/// <summary>
	/// Protocol Independant Multicast
	/// </summary>
	PIM = IPPROTO_PIM,
	/// <summary>
	///	Pragmatic General Multicast
	/// </summary>
	PGM = IPPROTO_PGM,
	/// <summary>
	///	Layer 2 Tunneling Protocol
	/// </summary>
	L2TP = IPPROTO_L2TP,
	/// <summary>
	/// Stream Control Transmission Protocol
	/// </summary>
	SCTP = IPPROTO_SCTP,
	/// <summary>
	/// Raw Packet
	/// </summary>
	RAW = IPPROTO_RAW
};

/// <summary>
/// The socket recieve api flags
/// </summary>
enum class SocketRecieveFlags : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Process out of band data
	/// </summary>
	OutOfBand = 0x00000001L,
	/// <summary>
	/// Peeks at the incoming data
	/// </summary>
	Peek = 0x00000002L,
	/// <summary>
	/// Request completes only when buffer is full
	/// </summary>
	WaitAll = 0x00000008L
};

/// <summary>
/// The socket send api flags
/// </summary>
enum class SocketSendFlags : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// The data packets should not be routed
	/// </summary>
	NoRouting = 0x00000004L,
	/// <summary>
	/// Sends OOB data on a stream type socket
	/// </summary>
	SendOOB = 0x00000001L
};

/// <summary>
/// The socket shutdown api flags
/// </summary>
enum class SocketShutdownFlags : int
{
	/// <summary>
	/// Shut down the receiving channel
	/// </summary>
	Receive = 0x00000000L,
	/// <summary>
	/// Shut down the sending channel
	/// </summary>
	Send = 0x00000001L,
	/// <summary>
	/// Shut down both channels
	/// </summary>
	Both = 0x00000002L
};

/// <summary>
/// The socket event flags
/// </summary>
enum class SocketEvent : int
{
	/// <summary>
	/// The socket process has completed successfully
	/// </summary>
	Success = 0x00000000L,
	/// <summary>
	/// The socket process has started successfully
	/// </summary>
	Started = 0x00000001L,
	/// <summary>
	/// The socket process has shutdown successfully
	/// </summary>
	Shutdown = 0x00000002L,
	/// <summary>
	/// The socket connection was accepted
	/// </summary>
	Accepted = 0x00000003L,
	/// <summary>
	/// The socket connection was accepted
	/// </summary>
	Bound = 0x00000004L,
	/// <summary>
	/// The socket was closed successfully
	/// </summary>
	Closed = 0x00000005L,
	/// <summary>
	/// The socket was connected successfully
	/// </summary>
	Connected = 0x00000006L,
	/// <summary>
	/// The socket was created successfully
	/// </summary>
	Created = 0x00000007L,
	/// <summary>
	/// The socket was detached from the server
	/// </summary>
	Detached = 0x00000008L,
	/// <summary>
	/// The socket is in the listening state
	/// </summary>
	Listening = 0x00000009L,
	/// <summary>
	/// The socket has received data
	/// </summary>
	Received = 0x0000000AL,
	/// <summary>
	/// The socket has sent the data
	/// </summary>
	Sent = 0x0000000BL,
	/// <summary>
	/// The socket process has failed
	/// </summary>
	Failure = 0x00FFFFFFL
};

/// <summary>
/// A disposable socket class that wraps asychronous and sychronous network operations
/// </summary>
class Socket
{
public:

	socket_t m_rawSocket;
	bool m_isOwner;

	//~~~Constructors~~~//

	/// <summary>
	/// The default constructor, the socket is uninitialized
	/// </summary>
	Socket();

	/// <summary>
	/// Initialize the class with a socket_t type
	/// </summary>
	/// 
	/// <param name="Socket">The pointer to the socket used to initialize the socket state</param>
	/// <param name="Owner">The owner of the socket; local ownership is true, remote false</param>
	Socket(socket_t &Socket, bool Owner);

	/// <summary>
	/// The destructor
	/// </summary>
	virtual ~Socket();

	operator socket_t()
	{
		return m_rawSocket;
	}

	socket_t GetSocket() const
	{
		return m_rawSocket;
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// The Accept function permits an incoming connection attempt on the socket
	/// </summary>
	/// 
	/// <param name="Target">The socket that has been placed in the listening state</param>
	/// <param name="Psa">The connecting sockets address buffer</param>
	/// <param name="PsaLength">The connecting sockets address buffer length</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful connection raises the SocketChanged event with the SocketEvent::Accepted flag</remarks>
	bool Accept(Socket &Target, sockaddr* Psa = nullptr, socklen_t* PsaLength = nullptr);

	/// <summary>
	/// Attach a socket to the local socket
	/// </summary>
	/// 
	/// <param name="Socket">The socket to attach</param>
	/// <param name="Owner">The owner of the attached socket</param>
	void AttachSocket(socket_t &Socket, bool Owner);

	/// <summary>
	/// The Bind function associates an address with a socket
	/// </summary>
	/// 
	/// <param name="Target">The address port number</param>
	/// <param name="Psa">The address string</param>
	/// <param name="AddressFamily">The address family type; default is IPv4</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful binding raises the SocketChanged event with the SocketEvent::Bound flag</remarks>
	void Bind(ushort Port, const std::string &Address, SocketAddressFamilies AddressFamily = SocketAddressFamilies::IPv4);

	/// <summary>
	/// The Bind function associates an address with a socket
	/// </summary>
	/// 
	/// <param name="Psa">A pointer to the socket address structure</param>
	/// <param name="PsaLength">The size of the socket address structure</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful binding raises the SocketChanged event with the SocketEvent::Bound flag</remarks>
	void Bind(const sockaddr* Psa, socklen_t PsaLength);

	/// <summary>
	/// The Create function creates a socket that is bound to a specific transport provider
	/// </summary>
	/// 
	/// <param name="SocketType">A pointer to the socket address structure</param>
	///
	/// <remarks>Successful socket creation raises the SocketChanged event with the SocketEvent::Created flag</remarks>
	void Create(SocketAddressFamilies FamilyType = SocketAddressFamilies::IPv4, SocketTypes SocketType = SocketTypes::Stream, SocketProtocols ProtocolType = SocketProtocols::IPv4);

	/// <summary>
	/// The CloseSocket function closes and disposes of the socket
	/// </summary>
	///
	/// <remarks>Successful socket closure raises the SocketChanged event with the SocketEvent::Closed flag</remarks>
	void CloseSocket();

	/// <summary>
	/// The Connect function establishes a connection to a specified socket
	/// </summary>
	/// 
	/// <param name="Address">The IP protocol address string</param>
	/// <param name="Port">The application port number</param>
	/// <param name="AddressFamily">The address family type; default is IPv4</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	/// <remarks>Successful connection raises the SocketChanged event with the SocketEvent::Connected flag</remarks>
	bool Connect(const std::string &Address, ushort Port, SocketAddressFamilies AddressFamily = SocketAddressFamilies::IPv4);

	/// <summary>
	/// The Connect function establishes a connection to a specified socket
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure</param>
	/// <param name="PsaLength">The size of the address structure</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	/// <remarks>Successful connection raises the SocketChanged event with the SocketEvent::Connected flag</remarks>
	bool Connect(const sockaddr* Psa, socklen_t PsaLength);

	/// <summary>
	/// Disconnect the socket from a connection
	/// </summary>
	///
	/// <returns>Returns the disconnected socket</returns>
	socket_t DetachSocket();

	/// <summary>
	/// Get the last error generated by the internal socket library
	/// </summary>
	///
	/// <returns>Returns the last error state</returns>
	static int GetLastError();

	/// <summary>
	/// Retrieves the address of the connected peer
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure containing the data</param>
	/// <param name="PsaLength">The size of the address structure</param>
	void GetPeerName(sockaddr* Psa, socklen_t* SaLength);

	/// <summary>
	/// Retrieves the local name of the socket
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure containing the data</param>
	/// <param name="PsaLength">The size of the address structure</param>
	void GetSocketName(sockaddr* Psa, socklen_t* PsaLength);

	/// <summary>
	/// Sets the IO mode of the socket
	/// </summary>
	/// 
	/// <param name="Command">The command to pass to the socket</param>
	/// <param name="Arguments">The command arguments</param>
	///
	/// <remarks>Successful completion raises the SocketChanged event with the SocketEvent::Success flag</remarks>
	void IOCtl(long Command, unsigned long* Arguments);

	/// <summary>
	/// Places the socket in the listening state, waiting for a connection
	/// </summary>
	/// 
	/// <param name="BackLog">The maximum pending connections queue length</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	/// <remarks>Successful change to listening state raises the SocketChanged event with the SocketEvent::Listening flag</remarks>
	void Listen(int BackLog = 5);

	/// <summary>
	/// Get the port number using the connection parameters
	/// </summary>
	/// 
	/// <param name="Name">The service name</param>
	/// <param name="Protocol">The protocol name</param>
	///
	/// <returns>The port number, or zero on failure</returns>
	static ushort PortNameToNumber(const std::string &Name, const std::string &Protocol = std::string("tcp"));

	/// <summary>
	/// Receive data from a connected socket or a bound connectionless socket
	/// </summary>
	/// 
	/// <param name="Output">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of the receive function</param>
	///
	/// <remarks>Successful receive operation raises the SocketChanged event with the SocketEvent::Received flag</remarks>
	uint Receive(std::vector<byte> &Output, SocketRecieveFlags Flags);

	/// <summary>
	/// Determines the status of a socket waiting for a synchronous connection
	/// </summary>
	/// 
	/// <param name="Buffer">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of this function</param>
	///
	/// <returns>Returns the ready state of the receive operation</returns>
	bool ReceiveReady(const timeval* Timeout);

	/// <summary>
	/// Sends data on a connected socket
	/// </summary>
	/// 
	/// <param name="Input">The input buffer containing the data to be transmitted</param>
	/// <param name="Length">The number of bytes to send</param>
	/// <param name="Flags">Flags that influence the behavior of the send function</param>
	///
	/// <remarks>Successful send operation raises the SocketChanged event with the SocketEvent::Sent flag</remarks>
	uint Send(const std::vector<byte>& Input, size_t Length, SocketSendFlags Flags);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Timeout">The maximum time to wait for a response from the socket</param>
	///
	/// <returns>Returns the ready state of the send operation</returns>
	bool SendReady(const timeval* Timeout);

	/// <summary>
	/// Set the last error generated by the socket library
	/// </summary>
	/// 
	/// <param name="ErrorCode">The error code</param>
	static void SetLastError(int ErrorCode);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Parameters">The shutdown parameters</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful change to shutdown state raises the SocketChanged event with the SocketEvent::ShutDown flag</remarks>
	void ShutDown(SocketShutdownFlags Parameters);

	/// <summary>
	/// Shut down the sockets library
	/// </summary>
	static void ShutDownSockets();

	/// <summary>
	/// Start the sockets library
	/// </summary>
	static void StartSockets();
};


class SocketsInitializer
{
public:
	SocketsInitializer() 
	{ 
		Socket::StartSockets();
	}

	~SocketsInitializer() 
	{ 
		try 
		{ 
			Socket::ShutDownSockets(); 
		} 
		catch (...) 
		{
		} 
	}
};

class SocketReceiver //: public NetworkReceiver
{
public:
	SocketReceiver(Socket &s);

#if defined (CEX_BERKELY_SOCKETS)
	bool MustWaitToReceive() { return true; }
#else
	~SocketReceiver();
	bool MustWaitForResult() { return true; }
#endif
	bool Receive(byte* buf, size_t bufLen);
	unsigned int GetReceiveResult();
	bool EofReceived() const { return m_eofReceived; }

	unsigned int GetMaxWaitObjectCount() const { return 1; }
	void GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack);

private:
	Socket &m_s;
	bool m_eofReceived;

#if defined (CEX_WINDOWS_SOCKETS)
	WindowsHandle m_event;
	OVERLAPPED m_overlapped;
	bool m_resultPending;
	DWORD m_lastResult;
#else
	unsigned int m_lastResult;
#endif
};

class SocketSender //: public NetworkSender
{
public:
	SocketSender(Socket &s);

#if defined (CEX_BERKELY_SOCKETS)
	bool MustWaitToSend() { return true; }
#else
	~SocketSender();
	bool MustWaitForResult() { return true; }
	bool MustWaitForEof() { return true; }
	bool EofSent();
#endif
	void Send(const byte* buf, size_t bufLen);
	unsigned int GetSendResult();
	void SendEof();

	unsigned int GetMaxWaitObjectCount() const { return 1; }
	void GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack);

private:
	Socket &m_s;
#if defined (CEX_WINDOWS_SOCKETS)
	WindowsHandle m_event;
	OVERLAPPED m_overlapped;
	bool m_resultPending;
	DWORD m_lastResult;
#else
	unsigned int m_lastResult;
#endif
};


/*//! socket-based implementation of NetworkSource
class SocketSource : public NetworkSource, public Socket
{
public:
	SocketSource(socket_t s = INVALID_SOCKET, bool pumpAll = false, BufferedTransformation *attachment = NULL)
		: NetworkSource(attachment), Socket(s), m_receiver(*this)
	{
		if (pumpAll)
			PumpAll();
	}

private:
	NetworkReceiver & AccessReceiver() { return m_receiver; }
	SocketReceiver m_receiver;
};

//! socket-based implementation of NetworkSink
class SocketSink : public NetworkSink, public Socket
{
public:
	SocketSink(socket_t s = INVALID_SOCKET, unsigned int maxBufferSize = 0, unsigned int autoFlushBound = 16 * 1024)
		: NetworkSink(maxBufferSize, autoFlushBound), Socket(s), m_sender(*this) {}

	void SendEof() { ShutDown(SD_SEND); }

private:
	NetworkSender & AccessSender() { return m_sender; }
	SocketSender m_sender;
};*/


NAMESPACE_NETWORKEND
#endif
