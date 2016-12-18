#ifndef _CEX_PRNGFROMNAME_H
#define _CEX_PRNGFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IPrng.h"

NAMESPACE_HELPER

using Prng::IPrng;
using Enumeration::Prngs;

/// <summary>
/// Get a Prng instance from it's enumeration name.
/// </summary>
class PrngFromName
{
public:
	/// <summary>
	/// Get a Prng instance with default initialization parameters
	/// </summary>
	/// 
	/// <param name="PrngType">The Prng enumeration name</param>
	/// 
	/// <returns>An initialized Prng</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IPrng* GetInstance(Prngs PrngType);
};

NAMESPACE_HELPEREND
#endif