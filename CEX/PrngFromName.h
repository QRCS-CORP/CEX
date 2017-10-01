#ifndef CEX_PRNGFROMNAME_H
#define CEX_PRNGFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "Digests.h"
#include "IPrng.h"
#include "Providers.h"

NAMESPACE_HELPER

using Enumeration::Digests;
using Prng::IPrng;
using Enumeration::Prngs;
using Enumeration::Providers;

/// <summary>
/// Get a Prng instance from it's enumeration name
/// </summary>
class PrngFromName
{
public:
	/// <summary>
	/// Get a Prng instance with default initialization parameters
	/// </summary>
	/// 
	/// <param name="PrngType">The Prng engines enumeration name</param>
	/// <param name="ProviderType">The entropy providers enumeration name; default is auto-seed</param>
	/// <param name="DigestType">The primary engine with HCG and DCG, or (optional) invokes HX cipher key expansion function in BCG</param>
	/// 
	/// <returns>An initialized Prng</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IPrng* GetInstance(Prngs PrngType, Providers ProviderType = Providers::ACP, Digests DigestType = Digests::None);
};

NAMESPACE_HELPEREND
#endif