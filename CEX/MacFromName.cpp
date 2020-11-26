#include "MacFromName.h"
#include "BlockCiphers.h"
#include "CMAC.h"
#include "CryptoMacException.h"
#include "HMAC.h"
#include "GMAC.h"
#include "KMAC.h"
#include "KPA.h"
#include "Poly1305.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Enumeration::SHA2Digests;
using Enumeration::KmacModes;
using Enumeration::KpaModes;

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
			case Macs::CMACRHXH256:
			{
				mptr = new CMAC(BlockCiphers::RHXH256);
				break;
			}
			case Macs::CMACRHXH512:
			{
				mptr = new CMAC(BlockCiphers::RHXH512);
				break;
			}
			case Macs::CMACRHXS256:
			{
				mptr = new CMAC(BlockCiphers::RHXS256);
				break;
			}
			case Macs::CMACRHXS512:
			{
				mptr = new CMAC(BlockCiphers::RHXS512);
				break;
			}
			case Macs::GMAC:
			{
				mptr = new GMAC(BlockCiphers::AES);
				break;
			}
			case Macs::GMACRHXH256:
			{
				mptr = new GMAC(BlockCiphers::RHXH256);
				break;
			}
			case Macs::GMACRHXH512:
			{
				mptr = new GMAC(BlockCiphers::RHXH512);
				break;
			}
			case Macs::GMACRHXS256:
			{
				mptr = new GMAC(BlockCiphers::RHXS256);
				break;
			}
			case Macs::GMACRHXS512:
			{
				mptr = new GMAC(BlockCiphers::RHXS512);
				break;
			}
			case Macs::HMACSHA2256:
			{
				mptr = new HMAC(SHA2Digests::SHA2256);
				break;
			}
			case Macs::HMACSHA2512:
			{
				mptr = new HMAC(SHA2Digests::SHA2512);
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
			case Macs::KPA128:
			{
				mptr = new KPA(KpaModes::KPA128);
				break;
			}
			case Macs::KPA256:
			{
				mptr = new KPA(KpaModes::KPA256);
				break;
			}
			case Macs::KPA512:
			{
				mptr = new KPA(KpaModes::KPA512);
				break;
			}
			case Macs::Poly1305:
			{
				mptr = new Poly1305;
				break;
			}
			default:
			{
				// invaild parameter
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
			case StreamAuthenticators::HMACSHA2256:
			{
				mptr = new HMAC(SHA2Digests::SHA2256);
				break;
			}
			case StreamAuthenticators::HMACSHA2512:
			{
				mptr = new HMAC(SHA2Digests::SHA2512);
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
				// invaild parameter
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
