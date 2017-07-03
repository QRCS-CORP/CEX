#include "PrngFromName.h"
#include "BlockCiphers.h"
#include "BCR.h"
#include "DCR.h"
#include "HCR.h"

NAMESPACE_HELPER

IPrng* PrngFromName::GetInstance(Prngs PrngType, Providers ProviderType, Digests DigestType)
{
	if (PrngType == Prngs::None)
		Exception::CryptoException("PrngFromName:GetPrng", "Prng type can not be none!");
	if (ProviderType == Providers::None)
		Exception::CryptoException("PrngFromName:GetPrng", "Prng type can not be none!");
	if (PrngType != Prngs::BCR && DigestType == Digests::None)
		Exception::CryptoException("PrngFromName:GetPrng", "Digest type can not be none when using Digest or HMAC based rng!");

	try
	{
		switch (PrngType)
		{
			case Prngs::BCR:
				return new Prng::BCR(Enumeration::BlockCiphers::AHX, ProviderType);
			case Prngs::DCR:
				return new Prng::DCR(DigestType, ProviderType);
			case Prngs::HCR:
				return new Prng::HCR(DigestType, ProviderType);
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