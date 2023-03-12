#ifndef CEX_SOCKETTYPES_H
#define CEX_SOCKETTYPES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket transmission type
/// </summary>
enum class SocketTransports : int32_t
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Streaming connection SOCK_STREAM
	/// </summary>
	Stream = 0x00000001L,
	/// <summary>
	/// Datagram connection SOCK_DGRAM
	/// </summary>
	Datagram = 0x00000002L,
	/// <summary>
	/// TCP Raw socket SOCK_RAW
	/// </summary>
	Raw = 0x00000003L,
	/// <summary>
	/// Reliable protocol SOCK_RDM
	/// </summary>
	Reliable = 0x00000004L,
	/// <summary>
	/// Sequenced packets SOCK_SEQPACKET
	/// </summary>
	Sequenced = 0x00000005L
};

NAMESPACE_ENUMERATIONEND
#endif
