#include "MacFromDescription.h"
#include "CMAC.h"
#include "HMAC.h"
#include "Macs.h"
#include "CryptoException.h"

NAMESPACE_HELPER

IMac* MacFromDescription::GetInstance(MacDescription &Description)
{
	try
	{
		switch (Description.MacType())
		{
		case Enumeration::Macs::CMAC:
			return new Mac::CMAC(Description.EngineType());
		case Enumeration::Macs::HMAC:
			return new Mac::HMAC(Description.HmacEngine());
		default:
			throw Exception::CryptoException("MacFromDescription:GetInstance", "The mac type is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("MacFromDescription:GetInstance", "The mac is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND