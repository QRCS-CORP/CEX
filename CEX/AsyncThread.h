#ifndef CEX_ASYNCTHREAD_H
#define CEX_ASYNCTHREAD_H

#include "CexDomain.h"
#include <thread>

NAMESPACE_NETWORK

/// <summary>
/// Internal Async Thread class
/// </summary>
class AsyncThread
{
public:

	std::thread* Instance;
	uint Identity;

	AsyncThread(std::thread* Instance, uint Identity)
		:
		Instance(Instance),
		Identity(Identity)
	{}

	~AsyncThread()
	{
		Identity = 0;
	}
};

NAMESPACE_NETWORKEND
#endif
