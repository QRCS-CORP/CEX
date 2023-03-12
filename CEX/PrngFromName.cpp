#include "PrngFromName.h"
#include "BlockCiphers.h"
#include "BCR.h"
#include "CpuDetect.h"
#include "CryptoRandomException.h"
#include "CSR.h"
#include "HCR.h"
#include "SHA2Digests.h"

NAMESPACE_HELPER

using Exception::CryptoRandomException;
using Enumeration::ErrorCodes;
using Enumeration::SHA2Digests;
using Enumeration::ShakeModes;

const std::string PrngFromName::CLASS_NAME("PrngFromName");

IPrng* PrngFromName::GetInstance(Prngs PrngType, Providers ProviderType)
{
	using namespace Prng;

	IPrng* rptr(nullptr);

	try
	{
		switch (PrngType)
		{
			case Prngs::BCR:
			{
				rptr = new BCR(ProviderType);
				break;
			}
			case Prngs::CSR:
			{
				rptr = new CSR(ShakeModes::SHAKE256, ProviderType);
				break;
			}
			case Prngs::CSRC512:
			{
				rptr = new CSR(ShakeModes::SHAKE512, ProviderType);
				break;
			}
			case Prngs::HCR:
			{
				rptr = new HCR(SHA2Digests::SHA2256, ProviderType);
				break;
			}
			case Prngs::HCRS512:
			{
				rptr = new HCR(SHA2Digests::SHA2256, ProviderType);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The Prng type can not be null!"), ErrorCodes::InvalidParam);
				break;
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
