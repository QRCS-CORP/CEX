#include "DrbgFromName.h"
#include "BCG.h"
#include "CSG.h"
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
