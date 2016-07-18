#include "PrngFromName.h"
#include "CSPPrng.h"
#include "CTRPrng.h"
#include "SP20Prng.h"
#include "DGCPrng.h"

NAMESPACE_HELPER

CEX::Prng::IRandom* PrngFromName::GetInstance(CEX::Enumeration::Prngs PrngType)
{
	switch (PrngType)
	{
		case CEX::Enumeration::Prngs::CSPPrng:
			return new CEX::Prng::CSPPrng();
		case CEX::Enumeration::Prngs::CTRPrng:
			return new CEX::Prng::CTRPrng();
		case CEX::Enumeration::Prngs::DGCPrng:
			return new CEX::Prng::DGCPrng();
		case CEX::Enumeration::Prngs::SP20Prng:
			return new CEX::Prng::SP20Prng();
		default:
#if defined(ENABLE_CPPEXCEPTIONS)
			throw CEX::Exception::CryptoException("PrngFromName:GetPrng", "The specified PRNG type is unrecognized!");
#else
			return 0;
#endif
	}
}

NAMESPACE_HELPEREND