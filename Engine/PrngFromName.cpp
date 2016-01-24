#include "PrngFromName.h"
#include "IRandom.h"
#include "CSPPrng.h"
#include "CTRPrng.h"
#include "SP20Prng.h"
#include "DGCPrng.h"

NAMESPACE_HELPER

using namespace CEX::Prng;

IRandom* PrngFromName::GetInstance(Prngs PrngType)
{
	switch (PrngType)
	{
		case Prngs::CSPPrng:
			return new CSPPrng();
		case Prngs::CTRPrng:
			return new CTRPrng();
		case Prngs::SP20Prng:
			return new SP20Prng();
		case Prngs::DGCPrng:
			return new DGCPrng();
		default:
			throw CryptoException("PrngFromName:GetPrng", "The specified PRNG type is unrecognized!");
	}
}

NAMESPACE_HELPEREND