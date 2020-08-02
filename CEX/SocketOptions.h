#ifndef CEX_SOCKETOPTIONS_H
#define CEX_SOCKETOPTIONS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// TCP socket options
/// </summary>
enum class SocketOptions : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Configures a socket for sending broadcast data SO_BROADCAST
	/// </summary>
	Broadcast = 0x00000020L,
	/// <summary>
	/// Enables sending keep-alive packets for a socket connection SO_KEEPALIVE
	/// </summary>
	KeepAlive = 0x00000008L,
	/// <summary>
	/// Lingers on close if unsent data is present SO_LINGER
	/// </summary>
	Linger = 0x00000080L,
	/// <summary>
	/// Sets whether outgoing data should be sent on interface the socket is bound to and not a routed on some other interface SO_DONTROUTE
	/// </summary>
	NoRoute = 0x00000010L,
	/// <summary>
	/// Indicates that out-of-bound data should be returned in-line with regular data SO_OOBINLINE
	/// </summary>
	OutOfBand = 0x00000100L,
	/// <summary>
	/// The timeout, in milliseconds, for blocking received calls SO_RCVTIMEO
	/// </summary>
	ReceiveTimeOut = 0x00001006L,
	/// <summary>
	/// The timeout, in milliseconds, for blocking send calls SO_SNDTIMEO
	/// </summary>
	SendTimeOut = 0x00001005L,
	/// <summary>
	/// Enables or disables the Nagle algorithm for TCP sockets. This option is disabled (set to FALSE) by default TCP_NODELAY
	/// </summary>
	TcpNoDelay = 0x00000001L
};

NAMESPACE_ENUMERATIONEND
#endif
