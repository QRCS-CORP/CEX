#ifndef _CEXENGINE_SEEDFROMNAME_H
#define _CEXENGINE_SEEDFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "ISeed.h"

NAMESPACE_HELPER

/// <summary>
/// SeedFromName: Get a seed generator instance from it's enumeration name
/// </summary>
class SeedFromName
{
public:
	/// <summary>
	/// Get a Seed Generator instance with default initialization parameters
	/// </summary>
	/// 
	/// <param name="SeedType">The seed generator enumeration name</param>
	/// 
	/// <returns>An initialized seed generator</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Seed::ISeed* GetInstance(CEX::Enumeration::SeedGenerators SeedType);
};

NAMESPACE_HELPEREND
#endif