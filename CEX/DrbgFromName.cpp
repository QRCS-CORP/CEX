#include "DrbgFromName.h"
#include "BCG.h"
#include "BlockCipherExtensions.h"
#include "BlockCiphers.h"
#include "CryptoGeneratorException.h"
#include "CSG.h"
#include "HCG.h"
#include "SHA2Digests.h"
#include "ShakeModes.h"

NAMESPACE_HELPER

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Exception::CryptoGeneratorException;
using Enumeration::ErrorCodes;

// TODO: Name and enumeral properties in helpers?
const std::string DrbgFromName::CLASS_NAME("DrbgFromName");

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType)
{
	using namespace Drbg;

	IDrbg* dptr;

	dptr = nullptr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				dptr = new BCG;
				break;
			}
			case Drbgs::CSG:
			{
				dptr = new CSG(ShakeModes::SHAKE256);
				break;
			}
			case Drbgs::HCG:
			{
				dptr = new HCG(SHA2Digests::SHA2512);
				break;
			}
			default:
			{
				// invalid parameter
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoGeneratorException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return dptr;
}

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType, Digests DigestType, Providers ProviderType)
{
	using namespace Drbg;

	IDrbg* dptr;

	dptr = nullptr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				dptr = new BCG(ProviderType);
				break;
			}
			case Drbgs::CSG:
			{
				dptr = new CSG(static_cast<Enumeration::ShakeModes>(DigestType), ProviderType);
				break;
			}
			case Drbgs::HCG:
			{
				dptr = new HCG(static_cast<Enumeration::SHA2Digests>(DigestType), ProviderType);
				break;
			}
			default:
			{
				// invalid parameter
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoGeneratorException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return dptr;
}

NAMESPACE_HELPEREND
