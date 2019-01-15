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
				dptr = new BCG();
				break;
			}
			case Drbgs::CSG:
			{
				dptr = new CSG();
				break;
			}
			case Drbgs::HCG:
			{
				dptr = new HCG();
				break;
			}
			default:
			{
				throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoGeneratorException &ex)
	{
		throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
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
				if (DigestType == Digests::SHA256)
				{
					dptr = new BCG(BlockCiphers::AHX, BlockCipherExtensions::HKDF256, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHAKE256)
				{
					dptr = new BCG(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHA512)
				{
					dptr = new BCG(BlockCiphers::AHX, BlockCipherExtensions::HKDF512, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHAKE512)
				{
					dptr = new BCG(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512, ProviderType);
					break;
				}
				else
				{
					throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
				}
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
				throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoGeneratorException &ex)
	{
		throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("DrbgFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return dptr;
}

NAMESPACE_HELPEREND
