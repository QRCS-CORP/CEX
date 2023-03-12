#ifndef CEX_SHUTDOWNFLAGS_H
#define CEX_SHUTDOWNFLAGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket shutdown api flags
/// </summary>
enum class SocketShutdownFlags : int32_t
{
	/// <summary>
	/// Shut down the receiving channel SD_RECEIVE
	/// </summary>
	Receive = 0x00000000L,
	/// <summary>
	/// Shut down the sending channel SD_SEND
	/// </summary>
	Send = 0x00000001L,
	/// <summary>
	/// Shut down both channels SD_BOTH
	/// </summary>
	Both = 0x00000002L
};

NAMESPACE_ENUMERATIONEND
#endif
