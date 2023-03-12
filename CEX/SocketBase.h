#ifndef CEX_SOCKETBASE_H
#define CEX_SOCKETBASE_H

#include "CexDomain.h"
#include "CryptoSocketException.h"
#include "EventHandler.h"
#include "InternetAddress.h"
#include "Socket.h"
#include "SocketExceptions.h"
#include "SocketEvents.h"
#include "SocketOptions.h"
#include "SocketReceiveFlags.h"
#include "SocketSendFlags.h"
#include "SocketShutdownFlags.h"

#if defined(CEX_OS_WINDOWS)
#	include <winsock2.h>
#	include <ws2def.h>
#	include <WS2tcpip.h>
#	include <inaddr.h>
#	include <iphlpapi.h>
#	pragma comment(lib, "ws2_32.lib")
#elif defined(CEX_OS_POSIX)
#	include <ifaddrs.h>
#	include <netinet/in.h> 
#	include <arpa/inet.h>
#	include <sys/socket.h>
#	include <sys/types.h>
#	include <unistd.h>
#else
#	error the operating system is unsupported! 
#endif

NAMESPACE_NETWORK

using Exception::CryptoSocketException;
using Enumeration::ErrorCodes;
using Enumeration::SocketEvents;
using Enumeration::SocketExceptions;
using Enumeration::SocketOptions;
using Enumeration::SocketReceiveFlags;
using Enumeration::SocketSendFlags;
using Enumeration::SocketShutdownFlags;

/// <summary>
/// The IPv4 information structure containing the address and port number
/// </summary>
typedef struct ipv4_info
{
	ipv4_address address;
	uint16_t port;
	uint8_t mask;
} ipv4_info;

/// <summary>
/// The IPv6 information structure containing the address and port number
/// </summary>
typedef struct ipv6_info
{
	ipv6_address address;
	uint16_t port;
	uint8_t mask;
} ipv6_info;

/// <summary>
/// The socket base class containing a socket instance
/// </summary>
class SocketBase final
{
public:

	//~~~Accessors~~~//

	/// <summary>
	/// Determines if the socket is in blocking mode
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	///
	/// <returns>Returns true if the source is blocking</returns>
	static bool IsBlocking(Socket &Source);

	/// <summary>
	/// Determines if the socket is connected
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	///
	/// <returns>Returns true if the source is connected</returns>
	static bool IsConnected(Socket &Source);

	//~~~Public Functions~~~//

	/// <summary>
	/// The Accept function permits an incoming connection attempt on the socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Target">The socket that has been placed in the listening state</param>
	///
	/// <returns>Returns true if the connection has been accepted</returns>
	static bool Accept(Socket &Source, Socket &Target);

	/// <summary>
	/// Attach a socket to the local socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Target">The socket to attach</param>
	static void Attach(Socket &Source, Socket &Target);

	/// <summary>
	/// The Bind function associates an address with a socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Address">The address to bind to the socket</param>
	/// <param name="Port">The service port number</param>
	///
	/// <returns>Returns true if the binding was successful</returns>
	static bool Bind(Socket &Source, const ipv4_address &Address, uint16_t Port);

	/// <summary>
	/// The Bind function associates an address with a socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Address">The address to bind to the socket</param>
	/// <param name="Port">The service port number</param>
	///
	/// <returns>Returns true if the binding was successful</returns>
	static bool Bind(Socket &Source, const ipv6_address &Address, uint16_t Port);

	/// <summary>
	/// The CloseSocket function closes and disposes of the socket
	/// </summary>
	///
	/// <param name="Source">The source socket instance</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket closure returns an error</exception>
	static void CloseSocket(Socket &Source);

	/// <summary>
	/// The Connect function establishes a connection to a remote host using IPv4 addressing
	/// </summary>
	///
	/// <param name="Source">The source socket instance</param>
	/// <param name="Address">The remote hosts IPv4 address</param>
	/// <param name="Port">The remote hosts service port number</param>
	///
	/// <returns>Returns true if the connection was successful</returns>
	static bool Connect(Socket &Source, const ipv4_address &Address, uint16_t Port);

	/// <summary>
	/// The Connect function establishes a connection to a remote host using IPv6 addressing
	/// </summary>
	///
	/// <param name="Source">The source socket instance</param>
	/// <param name="Address">The remote hosts IPv6 address</param>
	/// <param name="Port">The remote hosts service port number</param>
	///
	/// <returns>Returns true if the connection was successful</returns>
	static bool Connect(Socket &Source, const ipv6_address &Address, uint16_t Port);

	/// <summary>
	/// The Create function creates a socket that is bound to a specific transport provider
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	///
	/// <returns>Returns true if the socket was created successfully</returns>
	static bool Create(Socket &Source);

	/// <summary>
	/// Places the socket in the listening state, waiting for a connection
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="BackLog">The maximum pending connections queue length</param>
	static bool Listen(Socket &Source, int32_t BackLog = SOCKET_MAX_CONN);

	/// <summary>
	/// Receive data from a synchronous connected socket or a bound connectionless socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Output">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of the receive function</param>
	/// 
	/// <returns>The number of bytes received from the remote host</returns>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	static uint32_t Receive(Socket &Source, std::vector<uint8_t> &Output, SocketReceiveFlags Flags);

	/// <summary>
	/// Sends data on a connected socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Input">The input buffer containing the data to be transmitted</param>
	/// <param name="Length">The number of bytes to send</param>
	/// <param name="Flags">Flags that influence the behavior of the send function</param>
	/// 
	/// <returns>The number of bytes sent to the remote host</returns>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	static uint32_t Send(Socket &Source, const std::vector<uint8_t> &Input, size_t Length, SocketSendFlags Flags);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Source">The source socket used in the function</param>
	/// <param name="Parameters">The shutdown parameters</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket closure returns an error</exception>
	static void ShutDown(Socket &Source, SocketShutdownFlags Parameters);

	//~~~Helper Functions~~~//

	/// <summary>
	/// Get the last error generated by the internal socket library
	/// </summary>
	///
	/// <returns>Returns the last error state</returns>
	static SocketExceptions GetLastError();

	/// <summary>
	/// Sets the IO mode of the socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Command">The command to pass to the socket</param>
	/// <param name="Arguments">The command arguments</param>
	///
	/// <remarks>Successful completion raises the SocketChanged event with the SocketEvents::Success flag</remarks>
	static void IOCtl(Socket &Source, int64_t Command, uint64_t* Arguments);

	/// <summary>
	/// Determines the status of a socket waiting for a synchronous connection
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Timeout">The receive wait timeout</param>
	///
	/// <returns>Returns the ready state of the receive operation</returns>
	static bool ReceiveReady(Socket &Source, const timeval* Timeout);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Timeout">The maximum time to wait for a response from the socket</param>
	///
	/// <returns>Returns the ready state of the send operation</returns>
	static bool SendReady(Socket &Source, const timeval* Timeout);

	/// <summary>
	/// Set the last error generated by the socket library
	/// </summary>
	/// 
	/// <param name="ErrorCode">The error code</param>
	static void SetLastError(int32_t ErrorCode);

	/// <summary>
	/// Shut down the sockets library
	/// </summary>
	static void ShutDownSockets();

	/// <summary>
	/// Send an option command to the socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// <param name="Protocol">The ip protocol parameter</param>
	/// <param name="Option">The option command to send</param>
	static void SocketOption(Socket &Source, SocketProtocols Protocol = SocketProtocols::TCP, SocketOptions Option = SocketOptions::TcpNoDelay);

	/// <summary>
	/// Start the sockets library
	/// </summary>
	static void StartSockets();

private:

	static bool Acceptv4(Socket &Source, Socket &Target);
	static bool Acceptv6(Socket &Source, Socket &Target);
};


NAMESPACE_NETWORKEND
#endif