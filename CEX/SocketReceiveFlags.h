#ifndef CEX_RECEIVEFLAGS_H
#define CEX_RECEIVEFLAGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket receive api flags
/// </summary>
enum class SocketReceiveFlags : int
{
	/// <summary>
	/// No flag is used
	/// </summary>
	None = 0x00000000L,
	/// <summary>
	/// Process out of band data MSG_OOB
	/// </summary>
	OutOfBand = 0x00000001L,
	/// <summary>
	/// Peeks at the incoming data MSG_PEEK
	/// </summary>
	Peek = 0x00000002L,
	/// <summary>
	/// Request completes only when buffer is full MSG_WAITALL
	/// </summary>
	WaitAll = 0x00000008L
};

NAMESPACE_ENUMERATIONEND
#endif
