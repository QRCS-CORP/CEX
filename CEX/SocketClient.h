#ifndef CEX_SOCKETCLIENT_H
#define CEX_SOCKETCLIENT_H

#include "IAsyncResult.h"
#include "SocketBase.h"
#include "SocketExceptions.h"
#include <mutex>
#include <thread>

NAMESPACE_NETWORK

using Enumeration::SocketExceptions;

/// <summary>
/// A socket client class that wraps asychronous and sychronous network operations
/// </summary>
class SocketClient
{
private:

	Socket m_baseSocket;

public:

	//~~~Events~~~//

	/// <summary>
	/// Raised when an asychronous socket is connected to a remote host.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int, const std::string&> OnSocketConnected;

	/// <summary>
	/// Raised when an asychronous socket is disconnected from a remote host.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int, const std::string&> OnSocketDisconnected;

	/// <summary>
	/// Raised when an asychronous socket receives data from a remote host.
	/// <para>The event transmits an instance counter, and the data as a byte vector<para>
	/// </summary>
	event<int, const std::vector<byte>&> OnSocketReceived;

	/// <summary>
	/// Raised when an asychronous socket has completed sending data to a remote host.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int> OnSocketSent;

	/// <summary>
	/// Raised when a socket encounters an error.
	/// <para>The event transmits an error code, and the error message.
	/// The error event messaging is used in place of exceptions for non-critical error messaging.<para>
	/// </summary>
	event<SocketExceptions, const std::string&> OnSocketError;

	//~~~Constructors~~~//

	/// <summary>
	/// The primary constructor
	/// </summary>
	/// 
	/// <param name="AddressFamily">The socket address family type</param>
	/// <param name="SocketProtocol">The socket protocol type</param>
	/// <param name="SocketTransport">The socket transport type</param>
	SocketClient(SocketAddressFamilies AddressFamily = SocketAddressFamilies::IPv4,
		SocketProtocols SocketProtocol = SocketProtocols::TCP, SocketTransports SocketTransport = SocketTransports::Stream);

	/// <summary>
	/// The copy constructor
	/// </summary>
	/// 
	/// <param name="Source">The source socket to initialize the class with</param>
	SocketClient(Socket &Source);

	/// <summary>
	/// The destructor
	/// </summary>
	~SocketClient();

	//~~~Accessors~~~//

	/// <summary>
	/// Get: The sockets address family, IPv4 or IPv6
	/// </summary>
	SocketAddressFamilies AddressFamily();

	/// <summary>
	/// Get/Set: The raw socket structure
	/// </summary>
	Socket &BaseSocket();

	/// <summary>
	/// Get: The socket protocol type
	/// </summary>
	SocketProtocols SocketProtocol();

	/// <summary>
	/// Get: The socket transport type
	/// </summary>
	SocketTransports SocketTransport();

	//~~~Public Functions~~~//

	/// <summary>
	/// The Connect function establishes a connection to a remote host
	/// </summary>
	///
	/// <param name="Host">The remote host name</param>
	/// <param name="Service">The connection service name</param>
	bool Connect(const std::string &Host, std::string &Service);

	/// <summary>
	/// The Connect function establishes a connection to a remote host using IPv4 addressing
	/// </summary>
	///
	/// <param name="Address">The remote hosts IPv4 address</param>
	/// <param name="Port">The remote hosts service port number</param>
	bool Connect(const ipv4_address &Address, ushort Port);

	/// <summary>
	/// The Connect function establishes a connection to a remote host using IPv6 addressing
	/// </summary>
	///
	/// <param name="Address">The remote hosts IPv6 address</param>
	/// <param name="Port">The remote hosts service port number</param>
	bool Connect(const ipv6_address &Address, ushort Port);

	/// <summary>
	/// Start Non-Blocking connect to a remote host
	/// </summary>
	/// 
	/// <param name="Address">The IP protocol address string</param>
	/// <param name="Port">The application port number</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp connect operation has failed</exception>
	void ConnectAsync(const std::string &Address, ushort Port);

	/// <summary>
	/// The async connect callback
	/// </summary>
	void ConnectCallback(IAsyncResult* Result);

	/// <summary>
	/// Receive data from a synchronous connected socket or a bound connectionless socket.
	/// <para>Uses the OnSocketReceived event to return data to the caller.</para>
	/// </summary>
	/// 
	/// <param name="BufferLength">The size of the receiving buffer</param>
	/// <param name="Flags">Flags that influence the behavior of the receive function</param>
	/// 
	/// <returns>The number of bytes received from the remote host</returns>
	///
	/// <remarks>Requires the OnSocketReceived event handler.</remarks>
	uint Receive(size_t BufferLength, SocketReceiveFlags Flags = SocketReceiveFlags::None);

	/// <summary>
	/// Receive data from a synchronous connected socket or a bound connectionless socket
	/// </summary>
	/// 
	/// <param name="Output">The buffer that receives incoming data</param>
	/// <param name="Flags">Flags that influence the behavior of the receive function</param>
	/// 
	/// <returns>The number of bytes received from the remote host</returns>
	///
	/// <remarks>Successful receive operation raises the SocketChanged event with the SocketEvents::Received flag</remarks>
	uint Receive(std::vector<byte> &Output, SocketReceiveFlags Flags = SocketReceiveFlags::None);

	/// <summary>
	/// Begin Non-Blocking receiver of incoming messages (called after a connection is made)
	/// </summary>
	/// 
	/// <param name="BufferLength">The byte length of the input buffer</param>
	/// <param name="Flags">The bitwise combination of Socket Flags (default is None)</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp receive operation has failed</exception>
	void ReceiveAsync(size_t BufferLength, SocketReceiveFlags Flags);

	/// <summary>
	/// The ReceiveAsync callback
	/// </summary>
	/// 
	/// <param name="Result">The asynchronous result structure</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown on socket error or if the Tcp stream is larger than the maximum allocation size</exception>
	void ReceiveCallback(IAsyncResult* Result);

	/// <summary>
	/// Sends data on a connected socket
	/// </summary>
	/// 
	/// <param name="Input">The input buffer containing the data to be transmitted</param>
	/// <param name="Length">The number of bytes to send</param>
	/// <param name="Flags">Flags that influence the behavior of the send function</param>
	/// 
	/// <returns>The number of bytes sent to the remote host</returns>
	///
	/// <remarks>Successful send operation raises the SocketChanged event with the SocketEvents::Sent flag</remarks>
	uint Send(const std::vector<byte> &Input, size_t Length, SocketSendFlags Flags = SocketSendFlags::SendOOB);

	/// <summary>
	/// Non-blocking transmission of data to the remote host
	/// </summary>
	/// 
	/// <param name="Input">The input buffer containing the data to be transmitted</param>
	/// <param name="Length">The number of bytes to send</param>
	/// <param name="Flags">Flags that influence the behavior of the send function</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp Send operation has failed, or the maximum allocation size is exceeded</exception>
	void SendAsync(const std::vector<byte> &Input, size_t Length, SocketSendFlags Flags);

	/// <summary>
	/// The Send callback
	/// </summary>
	/// 
	/// <param name="Result">The asynchronous result structure</param>
	void SendCallback(IAsyncResult* Result);

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful change to shutdown state raises the SocketChanged event with the SocketEvents::ShutDown flag</remarks>
	void ShutDown();
};

NAMESPACE_NETWORKEND
#endif