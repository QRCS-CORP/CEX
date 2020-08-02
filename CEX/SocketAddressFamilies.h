#ifndef CEX_SOCKETADDRESSFAMILIES_H
#define CEX_SOCKETADDRESSFAMILIES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket address family type
/// </summary>
enum class SocketAddressFamilies : int
{
	/// <summary>
	/// No address family is specified AF_UNSPEC
	/// </summary>
	None = 0x00000000L,
	///// <summary>
	///// Unix local to host (pipes, portals) AF_UNIX
	///// </summary>
	//UNIX = 0x00000001L,
	/// <summary>
	/// The Internet Protocol 4 address family AF_INET
	/// </summary>
	IPv4 = 0x00000002L,
	/// <summary>
	/// The Internet Protocol 6 address family AF_INET6
	/// </summary>
	IPv6 = 0x00000017L
};

NAMESPACE_ENUMERATIONEND
#endif
