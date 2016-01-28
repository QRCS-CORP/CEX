#ifndef _CEXENGINE_SEEDFROMNAME_H
#define _CEXENGINE_SEEDFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "ISeed.h"
#include "SeedGenerators.h"

NAMESPACE_HELPER

using CEX::Seed::ISeed;
using CEX::Enumeration::SeedGenerators;
using CEX::Exception::CryptoException;

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
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static ISeed* GetInstance(SeedGenerators SeedType);
};

NAMESPACE_HELPEREND
#endif