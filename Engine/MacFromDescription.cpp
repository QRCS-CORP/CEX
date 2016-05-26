#include "MacFromDescription.h"
#include "CMAC.h"
#include "HMAC.h"
#include "VMAC.h"
#include "Macs.h"
#include "CryptoException.h"

NAMESPACE_HELPER

CEX::Mac::IMac* MacFromDescription::GetInstance(CEX::Common::MacDescription &Description)
{
	switch (Description.MacType())
	{
	case CEX::Enumeration::Macs::CMAC:
	{
		return new CEX::Mac::CMAC(Description.EngineType());
	}
	case CEX::Enumeration::Macs::HMAC:
	{
		return new CEX::Mac::HMAC(Description.HmacEngine());
	}
	case CEX::Enumeration::Macs::VMAC:
	{
		return new CEX::Mac::VMAC();
	}
	default:
		throw CEX::Exception::CryptoException("MacFromDescription:GetInstance", "The symmetric cipher is not recognized!");
	}
}

NAMESPACE_HELPEREND