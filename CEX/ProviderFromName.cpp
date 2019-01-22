#include "ProviderFromName.h"
#include "ACP.h"
#include "CJP.h"
#include "CpuDetect.h"
#include "CryptoRandomException.h"
#include "CSP.h"
#include "ECP.h"
#include "RDP.h"

NAMESPACE_HELPER

using Exception::CryptoRandomException;
using Enumeration::ErrorCodes;

const std::string ProviderFromName::CLASS_NAME("ProviderFromName");

IProvider* ProviderFromName::GetInstance(Providers ProviderType)
{
	IProvider* rndPtr = nullptr;
	CpuDetect detect;

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
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The entropy provider type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoRandomException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return rndPtr;
}

NAMESPACE_HELPEREND
