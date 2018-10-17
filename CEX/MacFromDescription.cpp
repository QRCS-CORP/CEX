#include "MacFromDescription.h"
#include "CMAC.h"
#include "HMAC.h"
#include "GMAC.h"
#include "KMAC.h"
#include "Poly1305.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

IMac* MacFromDescription::GetInstance(MacDescription &Description)
{
	IMac* macPtr = nullptr;

	try
	{
		switch (Description.MacType())
		{
			case Enumeration::Macs::CMAC:
			{
				macPtr = new Mac::CMAC(Description.CipherType(), Description.CipherExtension());
				break;
			}
			case Enumeration::Macs::HMAC:
			{
				macPtr = new Mac::HMAC(static_cast<Enumeration::SHA2Digests>(Description.MacDigest()));
				break;
			}
			case Enumeration::Macs::GMAC:
			{
				macPtr = new Mac::GMAC(Description.CipherType(), Description.CipherExtension());
				break;
			}
			case Enumeration::Macs::KMAC:
			{
				macPtr = new Mac::KMAC;
				break;
			}
			case Enumeration::Macs::Poly1305:
			{
				macPtr = new Mac::Poly1305;
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
