#ifndef CEX_SOCKETCONTAINER_H
#define CEX_SOCKETCONTAINER_H

#include "Socket.h"

NAMESPACE_NETWORK

/// <summary>
/// Internal socket container class
/// </summary>
class SocketContainer
{
public:

	Socket* Instance;
	ulong Interval;

	SocketContainer(Socket* Instance, ulong Interval)
		:
		Instance(Instance),
		Interval(Interval)
	{
	}

	~SocketContainer()
	{
		if (Instance != nullptr)
		{
			delete Instance;
		}

		Interval = 0;
	}
};

NAMESPACE_NETWORKEND
#endif
