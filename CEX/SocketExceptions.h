#ifndef CEX_SOCKETEXCEPTIONS_H
#define CEX_SOCKETEXCEPTIONS_H

#include "CexDomain.h"
#if defined(CEX_OS_WINDOWS)
#	include <winerror.h>
#else
#	include <errno.h>
#endif

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric AEAD cipher mode enumeration names
/// </summary>
enum class SocketExceptions : int
{
	/// <summary>
	/// No cipher mode is specified
	/// </summary>
	None = 0,
#if defined(CEX_OS_WINDOWS)
	/// <summary>
	/// The network subsystem has failed
	/// </summary>
	NetworkFailed = WSAENETDOWN,
	/// <summary>
	/// The requested address is a broadcast address, but the appropriate flag was not set
	/// </summary>
	BroadcastAddress = WSAEACCES,
	/// <summary>
	/// A blocking Windows Sockets 1.1 call was canceled through WSACancelBlockingCall
	/// </summary>
	BlockingCancelled = WSAEINTR,
	/// <summary>
	/// A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function
	/// </summary>
	BlockingInProgress = WSAEINPROGRESS,
	/// <summary>
	/// The buf parameter is not completely contained in a valid part of the user address space
	/// </summary>
	AddressBufferFault = WSAEFAULT,
	/// <summary>
	/// The connection has been broken due to the keep-alive activity detecting a failure while the operation was in progress
	/// </summary>
	KeepAliveFail = WSAENETRESET,
	/// <summary>
	/// No buffer space is available
	/// </summary>
	NoBufferSpace = WSAENOBUFS,
	/// <summary>
	/// The socket is not connected
	/// </summary>
	NotConnected = WSAENOTCONN,
	/// <summary>
	/// The descriptor is not a socket
	/// </summary>
	DescriptorNotSocket = WSAENOTSOCK,
	/// <summary>
	/// The socket has been shut down; it is not possible to send on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH
	/// </summary>
	SocketShutDown = WSAESHUTDOWN,
	/// <summary>
	/// The socket is marked as nonblocking and the requested operation would block
	/// </summary>
	SocketWouldBlock = WSAEWOULDBLOCK,
	/// <summary>
	/// The socket is message oriented, and the message is larger than the maximum supported by the underlying transport
	/// </summary>
	SocketMessageOriented = WSAEMSGSIZE,
	/// <summary>
	/// The remote host cannot be reached from this host at this time
	/// </summary>
	SocketHostUnreachable = WSAEHOSTUNREACH,
	/// <summary>
	/// The socket has not been bound with bind, or an unknown flag was specified, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled
	/// </summary>
	SocketNotBound = WSAEINVAL,
	/// <summary>
	/// The virtual circuit was terminated due to a time-out or other failure. The application should close the socket as it is no longer usable
	/// </summary>
	SocketCircuitTerminated = WSAECONNABORTED,
	/// <summary>
	/// The virtual circuit was reset by the remote side executing a hard or abortive close. 
	/// For UDP sockets, the remote host was unable to deliver a previously sent UDP datagram and responded with a "Port Unreachable" ICMP packet. 
	/// The application should close the socket as it is no longer usable.
	/// </summary>
	SocketCircuitReset = WSAECONNRESET,
	/// <summary>
	/// The connection has been dropped, because of a network failure or because the system on the other end went down without notice
	/// </summary>
	SocketCircuitTimeout = WSAETIMEDOUT,
	/// <summary>
	/// A successful WSAStartup call must occur before using this function
	/// </summary>
	SocketNotInitialized = WSANOTINITIALISED,
	/// <summary>
	/// The socket's local address is already in use and the socket was not marked to allow address reuse with SO_REUSEADDR. 
	/// This error usually occurs during execution of the bind function, but could be delayed until this function if the bind was to a partially wildcard address 
	/// (involving ADDR_ANY) and if a specific address needs to be committed at the time of this function. 
	/// </summary>
	SocketAddressInUse = WSAEADDRINUSE,
	/// <summary>
	/// The socket is already connected
	/// </summary>
	SocketAlreadyInUse = WSAEISCONN,
	/// <summary>
	/// No more socket descriptors are available
	/// </summary>
	SocketNoDescriptors = WSAEMFILE,
	/// <summary>
	/// The referenced socket is not of a type that supports the operation
	/// </summary>
	SocketNotListener = WSAEOPNOTSUPP,
#else
	/// <summary>
	/// Operation would block
	/// </summary>
	SocketNotAvailable = EWOULDBLOCK,
	/// <summary>
	/// Operation now in progress
	/// </summary>
	SocketIsProgress = EINPROGRESS,
	/// <summary>
	/// Operation already in progress
	/// </summary>
	SocketIsProcessing = EALREADY,
	/// <summary>
	/// Socket operation on non-socket
	/// </summary>
	SocketIsInvalid = ENOTSOCK,
	/// <summary>
	/// Destination address required
	/// </summary>
	SocketNoDestination = EDESTADDRREQ,
	/// <summary>
	/// Message too long
	/// </summary>
	SocketMessageTooLong = EMSGSIZE,
	/// <summary>
	/// Protocol wrong type for socket
	/// </summary>
	SocketProtocolWrongType = EPROTOTYPE,
	/// <summary>
	/// Protocol not available
	/// </summary>
	SocketProtocolNotAvailable = ENOPROTOOPT,
	/// <summary>
	/// Protocol not supported
	/// </summary>
	SocketProtocolNotSupported = EPROTONOSUPPORT,
	/// <summary>
	/// Socket type not supported
	/// </summary>
	SocketNotSupported = ESOCKTNOSUPPORT,
	/// <summary>
	/// Operation not supported on socket
	/// </summary>
	SocketOperationNotSupported = EOPNOTSUPP,
	/// <summary>
	/// Protocol family not supported
	/// </summary>
	SocketFamilyNotSupported = EPFNOSUPPORT,
	/// <summary>
	/// Address already in use
	/// </summary>
	SocketAddressInUse = EADDRINUSE,
	/// <summary>
	/// Can't assign requested address
	/// </summary>
	SocketInvalidAddress = EADDRNOTAVAIL,
	/// <summary>
	/// Network is down
	/// </summary>
	SocketNetworkDown = ENETDOWN,
	/// <summary>
	/// Network is unreachable
	/// </summary>
	SocketNetworkUnreachable = ENETUNREACH,
	/// <summary>
	/// Network dropped connection on reset
	/// </summary>
	SocketDroppedConnection = ENETRESET,
	/// <summary>
	/// Software caused connection abort
	/// </summary>
	SocketConnectedAbort = ECONNABORTED,
	/// <summary>
	/// Connection reset by peer
	/// </summary>
	SocketConnectionResetByPeer = ECONNRESET,
	/// <summary>
	/// No buffer space available
	/// </summary>
	SocketConnectionNoBuffer = ENOBUFS,
	/// <summary>
	/// Socket is already connected
	/// </summary>
	SocketAlreadyConnected = EISCONN,
	/// <summary>
	/// Socket is not connected
	/// </summary>
	SocketNotConnected = ENOTCONN,
	/// <summary>
	/// Can't send after socket shutdown
	/// </summary>
	SocketIsShutdown = ESHUTDOWN,
	/// <summary>
	/// Connection timed out
	/// </summary>
	SocketConnectionTimedOut = ETIMEDOUT,
	/// <summary>
	/// Connection refused
	/// </summary>
	SocketConnectionRefused = ECONNREFUSED,
#endif
};

NAMESPACE_ENUMERATIONEND
#endif
