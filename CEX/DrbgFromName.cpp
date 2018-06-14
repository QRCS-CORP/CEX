#include "DrbgFromName.h"
#include "BCG.h"
#include "CSG.h"
#include "HCG.h"

NAMESPACE_HELPER

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType)
{
	IDrbg* drbgPtr = nullptr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				drbgPtr = new Drbg::BCG();
				break;
			}
			case Drbgs::CSG:
			{
				drbgPtr = new Drbg::CSG();
				break;
			}
			case Drbgs::HCG:
			{
				drbgPtr = new Drbg::HCG();
				break;
			}
			default:
			{
				throw CryptoException("DrbgFromName:GetInstance", "The drbg is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("DrbgFromName:GetInstance", "The drbg is unavailable!", std::string(ex.what()));
	}

	return drbgPtr;
}

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType, Digests DigestType, Providers ProviderType)
{
	IDrbg* drbgPtr = nullptr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				if (DigestType == Digests::SHA256)
				{
					drbgPtr = new Drbg::BCG(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::HKDF256, ProviderType);
				}
				else if (DigestType == Digests::SHAKE256)
				{
					drbgPtr = new Drbg::BCG(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE256, ProviderType);
				}
				else if (DigestType == Digests::SHA512)
				{
					drbgPtr = new Drbg::BCG(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::HKDF512, ProviderType);
				}
				else if (DigestType == Digests::SHAKE512)
				{
					drbgPtr = new Drbg::BCG(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE512, ProviderType);
				}
				else
				{
					throw CryptoException("DrbgFromName:GetInstance", "The digest configuration is invalid!");
				}

				break;
			}
			case Drbgs::CSG:
			{

				drbgPtr = new Drbg::CSG(static_cast<Enumeration::ShakeModes>(DigestType), ProviderType);
				break;
			}
			case Drbgs::HCG:
			{
				drbgPtr = new Drbg::HCG(DigestType, ProviderType);
				break;
			}
			default:
			{
				throw CryptoException("DrbgFromName:GetInstance", "The drbg is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("DrbgFromName:GetInstance", "The drbg is unavailable!", std::string(ex.what()));
	}

	return drbgPtr;
}

NAMESPACE_HELPEREND
