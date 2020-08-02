#include "Socket.h"

NAMESPACE_NETWORK

//~~~Constructors~~~//

Socket::Socket(socket_t Source, SocketAddressFamilies AddressFamily, SocketProtocols Protocol, SocketTransports SocketTransport)
	:
	Connection(Source),
	Address(""),
	InstanceCount(0),
	Port(0),
	AddressFamily(AddressFamily),
	ConnectionStatus(SocketStates::None),
	SocketProtocol(Protocol),
	SocketTransport(SocketTransport)
{
}

Socket::Socket(SocketAddressFamilies AddressFamily, SocketProtocols Protocol, SocketTransports SocketTransport)
	:
	Connection(UNINITIALIZED_SOCKET),
	Address(""),
	InstanceCount(0),
	Port(0),
	AddressFamily(AddressFamily),
	ConnectionStatus(SocketStates::None),
	SocketProtocol(Protocol),
	SocketTransport(SocketTransport)
{
}

Socket::Socket()
	:
	Connection(UNINITIALIZED_SOCKET),
	Address(""),
	InstanceCount(0),
	Port(0),
	AddressFamily(SocketAddressFamilies::None),
	ConnectionStatus(SocketStates::None),
	SocketProtocol(SocketProtocols::None),
	SocketTransport(SocketTransports::None)
{
}

Socket::Socket(const Socket &Source)
	:
	Connection(Source.Connection),
	Address(Source.Address),
	InstanceCount(Source.InstanceCount),
	Port(Source.Port),
	AddressFamily(Source.AddressFamily),
	ConnectionStatus(Source.ConnectionStatus),
	SocketProtocol(Source.SocketProtocol),
	SocketTransport(Source.SocketTransport)
{
}

Socket::~Socket()
{
	AddressFamily = SocketAddressFamilies::None;
	SocketProtocol = SocketProtocols::None;
	SocketTransport = SocketTransports::None;

	Clear();
}

//~~~Public Functions~~~//

void Socket::Clear()
{
	Connection = 0;
	Address.clear();
	InstanceCount = 0;
	Port = 0;
	ConnectionStatus = SocketStates::None;
}


NAMESPACE_NETWORKEND
