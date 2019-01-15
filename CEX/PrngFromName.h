#ifndef CEX_PRNGFROMNAME_H
#define CEX_PRNGFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "Digests.h"
#include "IPrng.h"
#include "Providers.h"

NAMESPACE_HELPER

using Exception::CryptoException;
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
	/// Get a Prng instance with initialization parameters
	/// </summary>
	/// 
	/// <param name="PrngType">The rng engines enumeration name</param>
	/// <param name="ProviderType">The entropy providers enumeration name; default is auto-seed</param>
	/// 
	/// <returns>An initialized Prng</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IPrng* GetInstance(Prngs PrngType, Providers ProviderType = Providers::ACP);
};

NAMESPACE_HELPEREND
#endif
