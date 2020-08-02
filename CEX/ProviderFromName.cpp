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
	IProvider* rptr = nullptr;
	CpuDetect dtc;

	try
	{
		switch (ProviderType)
		{
			case Providers::ACP:
			{
				rptr = new Provider::ACP();
				break;
			}
			case Providers::CJP:
			{				
				if (dtc.RDTSCP())
				{
					rptr = new Provider::CJP();
				}
				else
				{
					rptr = new Provider::ECP();
				}
				break;
			}
			case Providers::CSP:
			{
				rptr = new Provider::CSP();
				break;
			}
			case Providers::ECP:
			{
				rptr = new Provider::ECP();
				break;
			}
			case Providers::RDP:
			{
				if (dtc.RDRAND())
				{
					rptr = new Provider::RDP();
				}
				else
				{
					rptr = new Provider::ECP();
				}
				break;
			}
			default:
			{
				// invalid parameter
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

	return rptr;
}

NAMESPACE_HELPEREND
