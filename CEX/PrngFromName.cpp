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

const std::string PrngFromName::CLASS_NAME("PrngFromName");

IPrng* PrngFromName::GetInstance(Prngs PrngType, Providers ProviderType)
{
	using namespace Prng;

	IPrng* rptr;

	rptr = nullptr;

	try
	{
		switch (PrngType)
		{
			case Prngs::BCR:
			{
				rptr = new BCR(Enumeration::BlockCiphers::AES, ProviderType);
				break;
			}
			case Prngs::BCRAHXS256:
			{
				rptr = new BCR(Enumeration::BlockCiphers::RHXS256, ProviderType);
				break;
			}
			case Prngs::BCRAHXS512:
			{
				rptr = new BCR(Enumeration::BlockCiphers::RHXS512, ProviderType);
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
			case Prngs::CSRC1024:
			{
				rptr = new CSR(ShakeModes::SHAKE1024, ProviderType);
				break;
			}
			case Prngs::HCR:
			{
				rptr = new HCR(Enumeration::SHA2Digests::SHA256, ProviderType);
				break;
			}
			case Prngs::HCRS512:
			{
				rptr = new HCR(Enumeration::SHA2Digests::SHA512, ProviderType);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The prng type is not supported!"), ErrorCodes::InvalidParam);
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
