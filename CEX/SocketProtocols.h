#ifndef CEX_SOCKETPROTOCOLS_H
#define CEX_SOCKETPROTOCOLS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket IP protocol type
/// </summary>
enum class SocketProtocols : int32_t
{
	/// <summary>
	/// No protocol type specified
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Internet Protocol version 4 IPPROTO_IPV4
	/// </summary>
	IPv4 = 0x00000004L,
	/// <summary>
	/// Transport Control Protocol IPPROTO_TCP
	/// </summary>
	TCP = 0x00000006L,
	/// <summary>
	/// Unreliable Delivery Protocol IPPROTO_UDP
	/// </summary>
	UDP = 0x00000011L,
	/// <summary>
	/// IPv6 header IPPROTO_IPV6
	/// </summary>
	IPv6 = 0x00000029L,
	/// <summary>
	/// IPv6 Routing header IPPROTO_ROUTING
	/// </summary>
	IPv6Routing = 0x0000002BL,
	/// <summary>
	/// IPv6 fragmentation header IPPROTO_FRAGMENT
	/// </summary>
	IPv6Fragment = 0x0000002CL,
	/// <summary>
	/// ICMPv6 IPPROTO_ICMPV6
	/// </summary>
	ICMPv6 = 0x0000003AL,
	/// <summary>
	/// IPv6 no next header IPPROTO_NONE
	/// </summary>
	IPv6NoHeader = 0x0000003BL,
	/// <summary>
	/// IPv6 Destination options IPPROTO_DSTOPTS
	/// </summary>
	DSTOPTS = 0x0000003CL,
	/// <summary>
	/// Raw Packet IPPROTO_RAW
	/// </summary>
	RAW = 0x000000FFL
};

NAMESPACE_ENUMERATIONEND
#endif
