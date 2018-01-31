#include "ProviderFromName.h"
#include "ACP.h"
#include "CJP.h"
#include "CpuDetect.h"
#include "CSP.h"
#include "ECP.h"
#include "RDP.h"

NAMESPACE_HELPER

IProvider* ProviderFromName::GetInstance(Providers ProviderType)
{
	IProvider* rndPtr;
	Common::CpuDetect detect;

	try
	{
		switch (ProviderType)
		{
			case Providers::ACP:
			{
				rndPtr = new Provider::ACP();
				break;
			}
			case Providers::CJP:
			{				
				if (detect.RDTSCP())
				{
					rndPtr = new Provider::CJP();
				}
				else
				{
					rndPtr = new Provider::ECP();
				}
				break;
			}
			case Providers::CSP:
			{
				rndPtr = new Provider::CSP();
				break;
			}
			case Providers::ECP:
			{
				rndPtr = new Provider::ECP();
				break;
			}
			case Providers::RDP:
			{
				if (detect.RDRAND())
				{
					rndPtr = new Provider::RDP();
				}
				else
				{
					rndPtr = new Provider::ECP();
				}
				break;
			}
			default:
			{
				throw CryptoException("ProviderFromName:GetInstance", "The specified entropy source type is unrecognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("ProviderFromName:GetInstance", "The specified entropy source type is unavailable!", std::string(ex.what()));
	}

	return rndPtr;
}

NAMESPACE_HELPEREND
