#ifndef CEX_SOCKET_H
#define CEX_SOCKET_H

#include "CexDomain.h"
#include "SocketAddressFamilies.h"
#include "SocketProtocols.h"
#include "SocketStates.h"
#include "SocketTransports.h"

NAMESPACE_NETWORK

using Enumeration::SocketAddressFamilies;
using Enumeration::SocketProtocols;
using Enumeration::SocketStates;
using Enumeration::SocketTransports;

typedef int32_t socklen_t;

#if defined(CEX_OS_WINDOWS)
typedef uintptr_t socket_t;
#else
typedef int32_t socket_t;
#endif

static const int32_t SOCKET_RET_ERROR = -1;
static const int32_t SOCKET_RET_SUCCESS = 0;
static const int32_t SOCKET_MAX_CONN = 0x7FFFFFFFL;
static const int32_t SOCKET_TIMEOUT_MSEC = 10000;

#if defined(CEX_OS_WINDOWS)
static const socket_t UNINITIALIZED_SOCKET = static_cast<uintptr_t>(~0);
#else
static const int32_t UNINITIALIZED_SOCKET = -1;
#endif

/// <summary>
/// The socket instance
/// </summary>
class Socket final
{
public:

	socket_t Connection;
	std::string Address;
	int32_t InstanceCount;
	uint16_t Port;
	SocketAddressFamilies AddressFamily;
	SocketStates ConnectionStatus;
	SocketProtocols SocketProtocol;
	SocketTransports SocketTransport;

	//~~~Constructor~~~//

	/// <summary>
	/// The primary socket constructor
	/// </summary>
	/// 
	/// <param name="Source">The socket instance pointer</param>
	/// <param name="AddressFamily">The socket address family type</param>
	/// <param name="Protocol">The socket protocol type</param>
	/// <param name="SocketTransport">The socket transport type</param>
	Socket(socket_t Source, SocketAddressFamilies AddressFamily, SocketProtocols Protocol, SocketTransports SocketTransport);

	/// <summary>
	/// The copyconstructor
	/// </summary>
	/// 
	/// <param name="Source">The source socket</param>
	Socket(const Socket &Source);

	/// <summary>
	/// The primary socket constructor
	/// </summary>
	/// 
	/// <param name="AddressFamily">The socket address family type</param>
	/// <param name="Protocol">The socket protocol type</param>
	/// <param name="SocketTransport">The socket transport type</param>
	Socket(SocketAddressFamilies AddressFamily, SocketProtocols Protocol, SocketTransports SocketTransport);

	/// <summary>
	/// The default socket constructor, initializes state to defaults
	/// </summary>
	Socket();

	/// <summary>
	/// The socket destructor
	/// </summary>
	~Socket();

	/// <summary>
	/// Move constructor
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	Socket(Socket &&Source) noexcept
		:
		Connection(std::move(Source.Connection)),
		Address(std::move(Source.Address)),
		InstanceCount(std::move(Source.InstanceCount)),
		Port(std::move(Source.Port)),
		AddressFamily(std::move(Source.AddressFamily)),
		ConnectionStatus(std::move(Source.ConnectionStatus)),
		SocketProtocol(std::move(Source.SocketProtocol)),
		SocketTransport(std::move(Source.SocketTransport))
	{
	}

	//~~~Operators~~~//

	/// <summary>
	/// Copy assignment operator
	/// </summary>
	///
	/// <param name="Source">The copy source</param>
	/// 
	/// <returns>A copy of the socket</returns>
	Socket& operator=(const Socket &Source)
	{
		Connection = Source.Connection;
		Address = Source.Address;
		InstanceCount = Source.InstanceCount;
		Port = Source.Port;
		AddressFamily = Source.AddressFamily;
		ConnectionStatus = Source.ConnectionStatus;
		SocketProtocol = Source.SocketProtocol;
		SocketTransport = Source.SocketTransport;

		return *this;
	}

	/// <summary>
	/// Move assignment operator
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	/// 
	/// <returns>The moved socket</returns>
	Socket& operator=(Socket&& Source) noexcept
	{
		std::swap(Connection, Source.Connection);
		std::swap(Address, Source.Address);
		std::swap(InstanceCount, Source.InstanceCount);
		std::swap(Port, Source.Port);
		std::swap(AddressFamily, Source.AddressFamily);
		std::swap(ConnectionStatus, Source.ConnectionStatus);
		std::swap(SocketProtocol, Source.SocketProtocol);
		std::swap(SocketTransport, Source.SocketTransport);

		return *this;
	}

	/// <summary>
	/// Test a socket for equivalance
	/// </summary>
	///
	/// <param name="Source">The address to compare</param>
	/// 
	/// <returns>Returns true for an equal socket</returns>
	bool operator==(const Socket &Source) const
	{
		return (Connection == Source.Connection &&
			Address == Source.Address &&
			InstanceCount == Source.InstanceCount &&
			Port == Source.Port &&
			AddressFamily == Source.AddressFamily &&
			ConnectionStatus == Source.ConnectionStatus &&
			SocketProtocol == Source.SocketProtocol &&
			SocketTransport == Source.SocketTransport);
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Set state to default values
	/// </summary>
	void Clear();
};


NAMESPACE_NETWORKEND
#endif
