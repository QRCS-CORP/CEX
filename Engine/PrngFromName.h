#ifndef _CEXENGINE_PRNGFROMNAME_H
#define _CEXENGINE_PRNGFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IRandom.h"
#include "Prngs.h"

NAMESPACE_HELPER

using CEX::Prng::IRandom;
using CEX::Enumeration::Prngs;
using CEX::Exception::CryptoException;

/// <summary>
/// PrngFromName: Get a Prng instance from it's enumeration name.
/// </summary>
class PrngFromName
{
public:
	/// <summary>
	/// Get a Prng instance with default initialization parameters
	/// </summary>
	/// 
	/// <param name="EngineType">The prng enumeration name</param>
	/// 
	/// <returns>An initialized prng</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static IRandom* GetInstance(Prngs PrngType);
};

NAMESPACE_HELPEREND
#endif