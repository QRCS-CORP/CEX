#include "MacFromName.h"
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
using Enumeration::ShakeModes;

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
				mptr = new CMAC(BlockCiphers::AHX);
				break;
			}
			case Macs::CMACAHXS256:
			{
				mptr = new CMAC(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256);
				break;
			}
			case Macs::CMACAHXS512:
			{
				mptr = new CMAC(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512);
				break;
			}
			case Macs::GMAC:
			{
				mptr = new GMAC(BlockCiphers::AHX);
				break;
			}
			case Macs::GMACAHXS256:
			{
				mptr = new GMAC(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256);
				break;
			}
			case Macs::GMACAHXS512:
			{
				mptr = new GMAC(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512);
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
				throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), std::string("The mac generator type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoMacException &ex)
	{
		throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
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
				mptr = new KMAC(ShakeModes::SHAKE256);
				break;
			}
			case StreamAuthenticators::KMAC512:
			{
				mptr = new KMAC(ShakeModes::SHAKE512);
				break;
			}
			case StreamAuthenticators::KMAC1024:
			{
				mptr = new KMAC(ShakeModes::SHAKE1024);
				break;
			}
			default:
			{
				throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), std::string("The mac generator type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoMacException &ex)
	{
		throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("MacFromDescription"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
