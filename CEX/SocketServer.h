#ifndef CEX_SOCKETSERVER_H
#define CEX_SOCKETSERVER_H

#include "AsyncThread.h"
#include "IAsyncResult.h"
#include "SocketBase.h"
#include "SocketExceptions.h"
#include <mutex>
#include <thread>

NAMESPACE_NETWORK

using Enumeration::SocketExceptions;

/// <summary>
/// A socket server class that wraps asychronous and sychronous network operations
/// </summary>
class SocketServer
{
private:

	static const uint DEF_BACKLOG = SOCKET_MAX_CONN;
	static const uint MAX_SOCKETS = 10000;

	class SocketServerState;

	std::unique_ptr<SocketServerState> m_socketServerState; 
	std::thread* m_ayncListener;

public:

	/// <summary>
	/// Raised when an asynchronous socket connection from a remote host has been accepted.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int, Socket&> OnAsyncSocketAccepted;

	/// <summary>
	/// Raised when a socket connection from a remote host has been accepted.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int, Socket&> OnSocketAccepted;

	/// <summary>
	/// Raised when a socket has been closed.
	/// <para>The event transmits an instance counter, and the address of the remote host<para>
	/// </summary>
	event<int, const std::string&> OnSocketClosed;

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
	SocketServer(SocketAddressFamilies AddressFamily = SocketAddressFamilies::IPv4, 
		SocketProtocols SocketProtocol = SocketProtocols::TCP, SocketTransports SocketTransport = SocketTransports::Stream);

	/// <summary>
	/// The destructor
	/// </summary>
	~SocketServer();

	//~~~Accessors~~~//

	/// <summary>
	/// Get: The sockets address family, IPv4 or IPv6
	/// </summary>
	SocketAddressFamilies AddressFamily();

	/// <summary>
	/// Get/Set: The maximum number of connections waiting in the listening queue
	/// </summary>
	uint &Backlog();

	/// <summary>
	/// Get: The listener operating state
	/// </summary>
	bool IsClosed();

	/// <summary>
	/// Get: The server listening state
	/// </summary>
	bool IsListening();

	/// <summary>
	/// Get/Set: The maximum number of simultaneous socket connections
	/// </summary>
	uint &MaxConnections();

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
	/// Places the socket in a blocking listening state, and waits for a connection.
	/// <para>The listening socket is destroyed after the connection is made. 
	/// Use the asynchronous sockets api for server-mode operations.</para>
	/// </summary>
	///
	/// <param name="Address">The IPv4 address</param>
	/// <param name="Port">The application port number</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket can not be created, fails to go into listening state, or the connection is refused</exception>
	/// <remarks><para>If the socket can not be created, the error code returned in the exception is SocketInvalid.
	/// If the socket can not be placed in the listening state the exception code is SocketFailure.
	/// If the connection to the remote socket is refused, the exception code is SocketRefused.</para></remarks>
	Socket Listen(const ipv4_address &Address, ushort Port);

	/// <summary>
	/// Places the socket in a blocking listening state, and waits for a connection.
	/// <para>The listening socket is destroyed after the connection is made. 
	/// Use the asynchronous sockets api for server-mode operations.</para>
	/// </summary>
	///
	/// <param name="Address">The IPv6 address</param>
	/// <param name="Port">The application port number</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket can not be created, fails to go into listening state, or the connection is refused</exception>
	/// <remarks><para>If the socket can not be created, the error code returned in the exception is SocketInvalid.
	/// If the socket can not be placed in the listening state the exception code is SocketFailure.
	/// If the connection to the remote socket is refused, the exception code is SocketRefused.</para></remarks>
	Socket Listen(const ipv6_address &Address, ushort Port);

	/// <summary>
	/// Start Non-Blocking listen on a port for an incoming connection
	/// </summary>
	/// 
	/// <param name="Address">The IPv4 address</param>
	/// <param name="Port">The application port number</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void ListenAsync(const ipv4_address &Address, ushort Port);

	/// <summary>
	/// Start Non-Blocking listen on a port for an incoming connection
	/// </summary>
	///
	/// <param name="Address">The IPv6 address</param>
	/// <param name="Port">The application port number</param>
	///
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void ListenAsync(const ipv6_address &Address, ushort Port);

	/// <summary>
	/// Stop listening for a connection
	/// </summary>
	void ListenStop();

	/// <summary>
	/// Tests the socket to see if it is ready to send data
	/// </summary>
	///
	/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
	/// <remarks>Successful change to shutdown state raises the SocketChanged event with the SocketEvents::ShutDown flag</remarks>
	void ShutDown();

private:

	void AcceptBegin();
	void AcceptEnd();
	void AcceptCallback(IAsyncResult* Result);
	uint PollSockets();
	void SetOptions();
};

NAMESPACE_NETWORKEND
#endif