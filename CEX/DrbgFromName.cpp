#include "DrbgFromName.h"
#include "BCG.h"
#include "DCG.h"
#include "HCG.h"

NAMESPACE_HELPER

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType)
{
	IDrbg* drbgPtr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				drbgPtr = new Drbg::BCG();
				break;
			}
			case Drbgs::DCG:
			{
				drbgPtr = new Drbg::DCG();
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
	IDrbg* drbgPtr;

	try
	{
		switch (DrbgType)
		{
			case Drbgs::BCG:
			{
				drbgPtr = new Drbg::BCG(BlockCiphers::AHX, DigestType, ProviderType);
				break;
			}
			case Drbgs::DCG:
			{
				drbgPtr = new Drbg::DCG(DigestType, ProviderType);
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
