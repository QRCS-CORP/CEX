#include "ProviderFromName.h"
#include "CJP.h"
#include "CSP.h"
#include "ECP.h"
#include "RDP.h"

NAMESPACE_HELPER

IProvider* ProviderFromName::GetInstance(Providers ProviderType)
{
	try
	{
		switch (ProviderType)
		{
		case Providers::CJP:
			return new Provider::CJP();
		case Providers::CSP:
			return new Provider::CSP();
		case Providers::ECP:
			return new Provider::ECP();
		case Providers::RDP:
			return new Provider::RDP();
		default:
			throw Exception::CryptoException("ProviderFromName:GetInstance", "The specified entropy source type is unrecognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("ProviderFromName:GetInstance", "The specified entropy source type is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND