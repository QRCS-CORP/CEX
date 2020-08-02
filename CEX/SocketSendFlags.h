#ifndef CEX_SENDFLAGS_H
#define CEX_SENDFLAGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket send api flags
/// </summary>
enum class SocketSendFlags : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Sends OOB data on a stream type socket MSG_OOB
	/// </summary>
	SendOOB = 0x00000001L,
	/// <summary>
	/// Sends a partial message
	/// </summary>
	PeekMessage = 0x00000002L,
	/// <summary>
	/// The data packets should not be routed MSG_DONTROUTE
	/// </summary>
	NoRouting = 0x00000004L,

};

NAMESPACE_ENUMERATIONEND
#endif
