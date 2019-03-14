#include "MacFromName.h"
#include "BlockCiphers.h"
#include "CMAC.h"
#include "CryptoMacException.h"
#include "HMAC.h"
#include "GMAC.h"
#include "KMAC.h"
#include "Poly1305.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Enumeration::SHA2Digests;
using Enumeration::KmacModes;

const std::string MacFromName::CLASS_NAME("MacFromName");

IMac* MacFromName::GetInstance(Macs MacType)
{
	using namespace Mac;

	IMac* mptr;

	mptr = nullptr;

	try
	{
		switch (MacType)
		{
		case Macs::CMAC:
			{
				mptr = new CMAC(BlockCiphers::AES);
				break;
			}
			case Macs::CMACAHXS256:
			{
				mptr = new CMAC(BlockCiphers::RHXS256);
				break;
			}
			case Macs::CMACAHXS512:
			{
				mptr = new CMAC(BlockCiphers::RHXS512);
				break;
			}
			case Macs::GMAC:
			{
				mptr = new GMAC(BlockCiphers::AES);
				break;
			}
			case Macs::GMACAHXS256:
			{
				mptr = new GMAC(BlockCiphers::RHXS256);
				break;
			}
			case Macs::GMACAHXS512:
			{
				mptr = new GMAC(BlockCiphers::RHXS512);
				break;
			}
			case Macs::HMACSHA256:
			{
				mptr = new HMAC(SHA2Digests::SHA256);
				break;
			}
			case Macs::HMACSHA512:
			{
				mptr = new HMAC(SHA2Digests::SHA512);
				break;
			}
			case Macs::KMAC256:
			{
				mptr = new KMAC(KmacModes::KMAC256);
				break;
			}
			case Macs::KMAC512:
			{
				mptr = new KMAC(KmacModes::KMAC512);
				break;
			}
			case Macs::KMAC1024:
			{
				mptr = new KMAC(KmacModes::KMAC1024);
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

IMac* MacFromName::GetInstance(StreamAuthenticators AuthenticatorType)
{
	using namespace Mac;

	IMac* mptr;

	mptr = nullptr;

	try
	{
		switch (AuthenticatorType)
		{
			case StreamAuthenticators::HMACSHA256:
			{
				mptr = new HMAC(SHA2Digests::SHA256);
				break;
			}
			case StreamAuthenticators::HMACSHA512:
			{
				mptr = new HMAC(SHA2Digests::SHA512);
				break;
			}
			case StreamAuthenticators::KMAC256:
			{
				mptr = new KMAC(KmacModes::KMAC256);
				break;
			}
			case StreamAuthenticators::KMAC512:
			{
				mptr = new KMAC(KmacModes::KMAC512);
				break;
			}
			case StreamAuthenticators::KMAC1024:
			{
				mptr = new KMAC(KmacModes::KMAC1024);
				break;
			}
			case StreamAuthenticators::Poly1305:
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
