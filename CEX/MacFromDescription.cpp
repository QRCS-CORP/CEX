#include "MacFromDescription.h"
#include "CMAC.h"
#include "HMAC.h"

NAMESPACE_HELPER

IMac* MacFromDescription::GetInstance(MacDescription &Description)
{
	IMac* macPtr;

	try
	{
		switch (Description.MacType())
		{
			case Enumeration::Macs::CMAC:
			{
				macPtr = new Mac::CMAC(Description.EngineType());
				break;
			}
			case Enumeration::Macs::HMAC:
			{
				macPtr = new Mac::HMAC(Description.HmacEngine());
				break;
			}
			default:
			{
				throw CryptoException("MacFromDescription:GetInstance", "The mac type is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("MacFromDescription:GetInstance", "The mac is unavailable!", std::string(ex.what()));
	}

	return macPtr;
}

NAMESPACE_HELPEREND
