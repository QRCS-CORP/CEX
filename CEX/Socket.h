#ifndef CEX_SOCKET_H
#define CEX_SOCKET_H

#include "CexDomain.h"
#include "CryptoSocketException.h"
#include "Event.h"
#include "IntegerTools.h"
#include "MemoryStream.h"
#include "MemoryTools.h"
#include "Mutex.h"
#include "Wait.h"

#if defined(CEX_WINDOWS_SOCKETS)
#	include <winsock2.h>
#else
#	include <sys/time.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <unistd.h>
#endif

NAMESPACE_NETWORK

#if !defined(INADDR_NONE)
#	define INADDR_NONE 0xFFFFFFFF
#endif

#if defined(CEX_WINDOWS_SOCKETS)
	const int SOCKET_EINVAL = WSAEINVAL;
	const int SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
	typedef int socklen_t;
	typedef ::SOCKET socket_t;
#else
	typedef int socket_t;
	const socket_t INVALID_SOCKET = -1;
	const int SD_RECEIVE = 0;
	const int SD_SEND = 1;
	const int SD_BOTH = 2;
	const int SOCKET_ERROR = -1;
	const int SOCKET_EINVAL = EINVAL;
	const int SOCKET_EWOULDBLOCK = EWOULDBLOCK;
#endif

using Exception::CryptoSocketException;
using Enumeration::ErrorCodes;
using Routing::Event;
using Utility::IntegerTools;
using IO::MemoryStream;
using Utility::MemoryTools;

enum class SocketAddressFamilyTypes : int
{
	/// <summary>
	/// No address family is specified
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// The Internet Protocol 4 address family
	/// </summary>
	IPv4 = 0x00000002L,
	/// <summary>
	/// The Internet Protocol 6 address family
	/// </summary>
	IPv6 = 0x00000017L
};

enum class SocketConnectionTypes : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Streaming connection
	/// </summary>
	Stream = 0x00000001L,
	/// <summary>
	/// Datagram connection
	/// </summary>
	Datagram = 0x00000002L,
	/// <summary>
	/// TCP Raw socket
	/// </summary>
	Raw = 0x00000003L,
	/// <summary>
	/// Reliable protocol
	/// </summary>
	Reliable = 0x00000004L,
	/// <summary>
	/// Sequenced packets
	/// </summary>
	Sequenced = 0x00000005L
};

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

enum class SocketShutdownFlags : int
{
	Receive = 0x00000000L,
	Send = 0x00000001L,
	Both = 0x00000002L
};

/// <summary>
/// A disposable socket class that wraps asychronous and sychronous network operations
/// </summary>
class Socket
{
private:
	
	socket_t m_socket;
	bool m_owner;

public:

	//~~~Events~~~//

	/// <summary>
	/// The socket changed event; raised when a socket operation has completed
	/// </summary>
	Event<int> SocketChanged;

	/// <summary>
	/// The socket received event; raised when data has been received on a socket connection
	/// </summary>
	Event<std::vector<byte>&> SocketReceived;

	//~~~Constructors~~~//

	/// <summary>
	/// The default constructor, the socket is uninitialized
	/// </summary>
	Socket();

	/// <summary>
	/// Initialize the class with a socket_t
	/// </summary>
	/// 
	/// <param name="Socket">The socket used to initialize the socket state</param>
	/// <param name="Owner">The owner of the socket</param>
	Socket(socket_t Socket = INVALID_SOCKET, bool Owner = false);

	/// <summary>
	/// Copy constructor; initialize the class with a Socket class
	/// </summary>
	/// 
	/// <param name="Socket">The socket used to initialize the socket state</param>
	Socket(const Socket &Socket);

	/// <summary>
	/// The destructor
	/// </summary>
	~Socket();

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
	/// <exception cref="CryptoSocketException">Thrown if the socket is rejected</exception>
	/// <remarks>Successful connection raises the SocketChanged event</remarks>
	bool Accept(Socket &Target, sockaddr* Psa, socklen_t* PsaLength);

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
	///
	/// <exception cref="CryptoSocketException">Thrown if the IP addres is invalid</exception>
	/// <remarks>Successful binding raises the SocketChanged event</remarks>
	void Bind(ushort Port, std::string &Address);

	/// <summary>
	/// The Bind function associates an address with a socket
	/// </summary>
	/// 
	/// <param name="Psa">A pointer to the socket address structure</param>
	/// <param name="PsaLength">The size of the socket address structure</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the address structure is invalid</exception>
	/// <remarks>Successful binding raises the SocketChanged event</remarks>
	void Bind(const sockaddr* Psa, socklen_t PsaLength);

	/// <summary>
	/// The Create function creates a socket that is bound to a specific transport provider
	/// </summary>
	/// 
	/// <param name="SocketType">A pointer to the socket address structure</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the address structure is invalid</exception>
	/// <remarks>Successful socket creation raises the SocketChanged event</remarks>
	void Create(SocketAddressFamilyTypes SocketType);

	/// <summary>
	/// The CloseSocket function closes and disposes of the socket
	/// </summary>
	///
	/// <exception cref="CryptoSocketException">Thrown if the close socket operation fails</exception>
	/// <remarks>Successful socket closure raises the SocketChanged event</remarks>
	void CloseSocket();

	/// <summary>
	/// The Connect function establishes a connection to a specified socket
	/// </summary>
	/// 
	/// <param name="Address">The IP protocol address string</param>
	/// <param name="Port">The application port number</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	/// <exception cref="CryptoSocketException">Thrown if the host can not be found</exception>
	/// <remarks>Successful connection raises the SocketChanged event</remarks>
	bool Connect(std::string &Address, ushort Port);

	/// <summary>
	/// The Connect function establishes a connection to a specified socket
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure</param>
	/// <param name="PsaLength">The size of the address structure</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	/// <exception cref="CryptoSocketException">Thrown if the connection fails</exception>
	/// <remarks>Successful connection raises the SocketChanged event</remarks>
	bool Connect(const sockaddr* Psa, socklen_t PsaLength);

	/// <summary>
	/// Disconnect the socket from a connection
	/// </summary>
	///
	/// <returns>Returns the disconnected socket</returns>
	/// <remarks>Successful disconnection raises the SocketChanged event</remarks>
	socket_t DetachSocket();

	/// <summary>
	/// Retrieves the address of the connected peer
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure containing the data</param>
	/// <param name="PsaLength">The size of the address structure</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the query fails</exception>
	void GetPeerName(sockaddr* Psa, socklen_t* SaLength);

	/// <summary>
	/// Retrieves the local name of the socket
	/// </summary>
	/// 
	/// <param name="Psa">The IP protocol address structure containing the data</param>
	/// <param name="PsaLength">The size of the address structure</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the query fails</exception>
	void GetSocketName(sockaddr* Psa, socklen_t* PsaLength);

	/// <summary>
	/// Sets the IO mode of the socket
	/// </summary>
	/// 
	/// <param name="Command">The command to pass to the socket</param>
	/// <param name="Arguments">The command arguments</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the IO mode change fails</exception>
	/// <remarks>Successful IO operation raises the SocketChanged event</remarks>
	void IOCtl(long Command, unsigned long* Arguments);

	/// <summary>
	/// Places the socket in the listening state, waiting for a connection
	/// </summary>
	/// 
	/// <param name="BackLog">The maximum pending connections queue length</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	/// <remarks>Successful change to listening state raises the SocketChanged event</remarks>
	void Listen(int BackLog);

	/// <summary>
	/// Get the port number using the connection parameters
	/// </summary>
	/// 
	/// <param name="Name">The service name</param>
	/// <param name="Protocol">The protocol name</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	ushort PortNameToNumber(const std::string &Name, const std::string &Protocol);

	/// <summary>
	/// Receive data from a connected socket or a bound connectionless socket
	/// </summary>
	/// 
	/// <param name="Output">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of the receive function</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	/// <remarks>Successful receive operation raises the SocketChanged event</remarks>
	uint Receive(std::vector<byte>& Output, SocketRecieveFlags Flags);

	/// <summary>
	/// Determines the status of a socket waiting for a synchronous connection
	/// </summary>
	/// 
	/// <param name="Buffer">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of this function</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	bool ReceiveReady(const timeval* Timeout);

	/// <summary>
	/// Sends data on a connected socket
	/// </summary>
	/// 
	/// <param name="Input">The input buffer containing the data to be transmitted</param>
	/// <param name="Length">The number of bytes to send</param>
	/// <param name="Flags">Flags that influence the behavior of the send function</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket fails to go into listening state</exception>
	/// <remarks>Successful send operation raises the SocketChanged event</remarks>
	uint Send(const std::vector<byte>& Input, size_t Length, SocketSendFlags Flags);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Timeout">The maximum time to wait for a response from the socket</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	bool SendReady(const timeval* Timeout);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Parameters">The shutdown parameters</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful change to shutdown state raises the SocketChanged event</remarks>
	void ShutDown(SocketShutdownFlags Parameters);

private:

	/// <summary>
	/// Terminates the winsock2 dll connection
	/// </summary>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful change to shutdown state raises the SocketChanged event</remarks>
	void ShutDownSockets();

	/// <summary>
	/// Initializes the winsock2 dll connection
	/// </summary>
	///
	/// <exception cref="CryptoSocketException">Thrown if winsock initialization returns an error</exception>
	/// <remarks>Successful winsock initialization raises the SocketChanged event</remarks>
	void StartSockets();

	int GetLastError();

	void SetLastError(int ErrorCode);
};


/*class SocketsInitializer
{
public:
	SocketsInitializer() { Socket::StartSockets(); }
	~SocketsInitializer() { try { Socket::ShutdownSockets(); } catch (...) {} }
};

class SocketReceiver : public NetworkReceiver
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
};*/

/*class SocketSender //: public NetworkSender
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
};*/

/* //! socket-based implementation of NetworkSource
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
