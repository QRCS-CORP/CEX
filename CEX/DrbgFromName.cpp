#include "DrbgFromName.h"
#include "BCG.h"
#include "DCG.h"
#include "HCG.h"

NAMESPACE_HELPER

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType)
{
	try
	{
		switch (DrbgType)
		{
		case Drbgs::BCG:
			return new Drbg::BCG();
		case Drbgs::DCG:
			return new Drbg::DCG();
		case Drbgs::HCG:
			return new Drbg::HCG();
		default:
			throw Exception::CryptoException("DrbgFromName:GetInstance", "The drbg is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DrbgFromName:GetInstance", "The drbg is unavailable!", std::string(ex.what()));
	}
}

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType, Digests DigestType, Providers ProviderType)
{
	try
	{
		switch (DrbgType)
		{
		case Drbgs::BCG:
			return new Drbg::BCG(BlockCiphers::AHX, DigestType, ProviderType);
		case Drbgs::DCG:
			return new Drbg::DCG(DigestType, ProviderType);
		case Drbgs::HCG:
			return new Drbg::HCG(DigestType, ProviderType);
		default:
			throw Exception::CryptoException("DrbgFromName:GetInstance", "The drbg is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DrbgFromName:GetInstance", "The drbg is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND