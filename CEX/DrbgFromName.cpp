#include "DrbgFromName.h"
#include "CMG.h"
#include "DCG.h"
#include "HMG.h"

NAMESPACE_HELPER

IDrbg* DrbgFromName::GetInstance(Drbgs DrbgType)
{
	try
	{
		switch (DrbgType)
		{
		case Drbgs::CMG:
			return new Drbg::CMG();
		case Drbgs::DCG:
			return new Drbg::DCG();
		case Drbgs::HMG:
			return new Drbg::HMG();
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
		case Drbgs::CMG:
			return new Drbg::CMG(BlockCiphers::AHX, DigestType, ProviderType);
		case Drbgs::DCG:
			return new Drbg::DCG(DigestType, ProviderType);
		case Drbgs::HMG:
			return new Drbg::HMG(DigestType, ProviderType);
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