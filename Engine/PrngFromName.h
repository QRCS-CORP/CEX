#ifndef _CEXENGINE_PRNGFROMNAME_H
#define _CEXENGINE_PRNGFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IRandom.h"

NAMESPACE_HELPER

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
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Prng::IRandom* GetInstance(CEX::Enumeration::Prngs PrngType);
};

NAMESPACE_HELPEREND
#endif