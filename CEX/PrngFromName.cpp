#include "PrngFromName.h"
#include "CMR.h"
#include "DCR.h"

NAMESPACE_HELPER

IPrng* PrngFromName::GetInstance(Prngs PrngType)
{
	try
	{
		switch (PrngType)
		{
			case Prngs::CMR:
				return new Prng::CMR();
			case Prngs::DCR:
				return new Prng::DCR();
			default:
				throw Exception::CryptoException("PrngFromName:GetPrng", "The specified prng type is unrecognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("PrngFromName:GetInstance", "The prng is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND