#ifndef CEX_SOCKETEVENTS_H
#define CEX_SOCKETEVENTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The socket event flags
/// </summary>
enum class SocketEvents : int
{
	/// <summary>
	/// The socket process has completed successfully
	/// </summary>
	Success = 0x00000000L,
	/// <summary>
	/// The socket process has started successfully
	/// </summary>
	Started = 0x00000001L,
	/// <summary>
	/// The socket process has shutdown successfully
	/// </summary>
	Shutdown = 0x00000002L,
	/// <summary>
	/// The socket connection was accepted
	/// </summary>
	Accepted = 0x00000003L,
	/// <summary>
	/// The socket connection was accepted
	/// </summary>
	Bound = 0x00000004L,
	/// <summary>
	/// The socket was closed successfully
	/// </summary>
	Closed = 0x00000005L,
	/// <summary>
	/// The socket was connected successfully
	/// </summary>
	Connected = 0x00000006L,
	/// <summary>
	/// The socket was created successfully
	/// </summary>
	Created = 0x00000007L,
	/// <summary>
	/// The socket was detached from the server
	/// </summary>
	Detached = 0x00000008L,
	/// <summary>
	/// The socket is in the listening state
	/// </summary>
	Listening = 0x00000009L,
	/// <summary>
	/// The socket has received data
	/// </summary>
	Received = 0x0000000AL,
	/// <summary>
	/// The socket has sent the data
	/// </summary>
	Sent = 0x0000000BL,
	/// <summary>
	/// The socket process has failed
	/// </summary>
	Failure = 0x00FFFFFFL
};

NAMESPACE_ENUMERATIONEND
#endif
