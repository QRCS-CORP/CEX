#include "MacFromDescription.h"
#include "CMAC.h"
#include "CryptoMacException.h"
#include "HMAC.h"
#include "GMAC.h"
#include "KMAC.h"
#include "Poly1305.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Enumeration::Macs;

const std::string MacFromDescription::CLASS_NAME("MacFromDescription");

IMac* MacFromDescription::GetInstance(MacDescription &Description)
{
	using namespace Mac;

	IMac* mptr;

	mptr = nullptr;

	try
	{
		switch (Description.MacType())
		{
			case Macs::CMAC:
			{
				mptr = new CMAC(Description.CipherType(), Description.CipherExtension());
				break;
			}
			case Macs::HMACSHA256:
			{
				mptr = new HMAC(Enumeration::SHA2Digests::SHA256);
				break;
			}
			case Macs::HMACSHA512:
			{
				mptr = new HMAC(Enumeration::SHA2Digests::SHA512);
				break;
			}
			case Macs::GMAC:
			{
				mptr = new GMAC(Description.CipherType(), Description.CipherExtension());
				break;
			}
			case Macs::KMAC128:
			{
				mptr = new KMAC(ShakeModes::SHAKE128);
				break;
			}
			case Macs::KMAC256:
			{
				mptr = new KMAC(ShakeModes::SHAKE256);
				break;
			}
			case Macs::KMAC512:
			{
				mptr = new KMAC(ShakeModes::SHAKE512);
				break;
			}
			case Macs::KMAC1024:
			{
				mptr = new KMAC(ShakeModes::SHAKE1024);
				break;
			}
			case Macs::Poly1305:
			{
				mptr = new Poly1305;
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The mac generator type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoMacException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
