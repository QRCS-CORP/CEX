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
				dptr = new BCG(BlockCiphers::AES);
				break;
			}
			case Drbgs::CSG:
			{
				dptr = new CSG(ShakeModes::SHAKE256);
				break;
			}
			case Drbgs::HCG:
			{
				dptr = new HCG(SHA2Digests::SHA512);
				break;
			}
			default:
			{
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
				if (DigestType == Digests::SHA256)
				{
					dptr = new BCG(BlockCiphers::RHXH256, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHAKE256)
				{
					dptr = new BCG(BlockCiphers::RHXS256, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHA512)
				{
					dptr = new BCG(BlockCiphers::RHXH512, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHAKE512)
				{
					dptr = new BCG(BlockCiphers::RHXS512, ProviderType);
					break;
				}
				else if (DigestType == Digests::SHAKE1024)
				{
					dptr = new BCG(BlockCiphers::RHXS1024, ProviderType);
					break;
				}
				else
				{
					throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The drbg type is not supported!"), ErrorCodes::InvalidParam);
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
