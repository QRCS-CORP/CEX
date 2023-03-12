#ifndef CEX_SOCKETSTATES_H
#define CEX_SOCKETSTATES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket instance current connection state
/// </summary>
enum class SocketStates : uint8_t
{
	/// <summary>
	/// The socket instance is not initialized
	/// </summary>
	None = 0,
	/// <summary>
	/// The socket instance is connected
	/// </summary>
	Connected = 1,
	/// <summary>
	/// The socket instance is listening
	/// </summary>
	Listening = 2
};


NAMESPACE_ENUMERATIONEND
#endif
