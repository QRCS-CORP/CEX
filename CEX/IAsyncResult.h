#ifndef CEX_IASYNCRESULT_H
#define CEX_IASYNCRESULT_H

#include "CexDomain.h"
#include "Socket.h"

NAMESPACE_NETWORK

/// <summary>
/// Internal Async Results class
/// </summary>
class IAsyncResult
{
public:

	Socket Parent;
	std::vector<uint8_t> Data;
	std::string Address;
	uint32_t Flag;
	uint32_t Option;

	IAsyncResult(const Socket &Parent, uint32_t Option)
		:
		Data(0),
		Address(0),
		Flag(0),
		Parent(Parent),
		Option(Option)
	{
	}

	IAsyncResult(const Socket &Parent, uint32_t Option, uint32_t Flag)
		:
		Data(0),
		Address(0),
		Flag(Flag),
		Parent(Parent),
		Option(Option)
	{
	}

	IAsyncResult(const Socket &Parent, const std::vector<uint8_t> Data, uint32_t Option, uint32_t Flag)
		:
		Data(Data),
		Address(0),
		Flag(Flag),
		Parent(Parent),
		Option(Option)
	{
	}

	IAsyncResult(const Socket &Parent, const std::string &Address, uint32_t Option)
		:
		Data(0),
		Address(Address),
		Flag(0),
		Parent(Parent),
		Option(Option)
	{
	}

	~IAsyncResult()
	{
		size_t i;

		if (Data.size() != 0)
		{
			for (i = 0; i < Data.size(); ++i)
			{
				Data[i] = 0;
			}

			Data.clear();
		}

		if (Address.size() != 0)
		{
			Address.clear();
		}

		Flag = 0;
		Option = 0;
	}
};

NAMESPACE_NETWORKEND
#endif
