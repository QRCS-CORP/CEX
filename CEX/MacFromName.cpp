#include "MacFromName.h"
#include "CMAC.h"
#include "HMAC.h"
#include "GMAC.h"
#include "KMAC.h"
#include "Poly1305.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

IMac* MacFromName::GetInstance(Macs MacType)
{
	IMac* macPtr = nullptr;

	try
	{
		switch (MacType)
		{
			case Macs::CMAC:
			{
				macPtr = new Mac::CMAC(Enumeration::BlockCiphers::AHX);
				break;
			}
			case Macs::HMAC:
			{
				macPtr = new Mac::HMAC(Enumeration::SHA2Digests::SHA256);
				break;
			}
			case Macs::GMAC:
			{
				macPtr = new Mac::GMAC(Enumeration::BlockCiphers::AHX);
				break;
			}
			case Macs::KMAC:
			{
				macPtr = new Mac::KMAC;
				break;
			}
			case Macs::Poly1305:
			{
				macPtr = new Mac::Poly1305;
				break;
			}
			default:
			{
				throw CryptoException("MacFromName:GetInstance", "The mac type is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("MacFromName:GetInstance", "The mac is unavailable!", std::string(ex.what()));
	}

	return macPtr;
}

IMac* MacFromName::GetInstance(StreamAuthenticators AuthenticatorType)
{
	IMac* macPtr = nullptr;

	try
	{
		switch (AuthenticatorType)
		{
		case StreamAuthenticators::HMACSHA256:
		{
			macPtr = new Mac::HMAC(Enumeration::SHA2Digests::SHA256);
			break;
		}
		case StreamAuthenticators::HMACSHA512:
		{
			macPtr = new Mac::HMAC(Enumeration::SHA2Digests::SHA512);
			break;
		}
		case Enumeration::StreamAuthenticators::KMAC256:
		{
			macPtr = new Mac::KMAC(Enumeration::ShakeModes::SHAKE256);
			break;
		}
		case Enumeration::StreamAuthenticators::KMAC512:
		{
			macPtr = new Mac::KMAC(Enumeration::ShakeModes::SHAKE512);
			break;
		}
		default:
		{
			throw CryptoException("MacFromName:GetInstance", "The mac type is not recognized!");
		}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("MacFromName:GetInstance", "The mac is unavailable!", std::string(ex.what()));
	}

	return macPtr;
}

NAMESPACE_HELPEREND
