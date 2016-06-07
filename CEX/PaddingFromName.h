#ifndef _CEXENGINE_PADDINGFROMNAME_H
#define _CEXENGINE_PADDINGFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IPadding.h"

NAMESPACE_HELPER

/// <summary>
/// PaddingFromName: Get a Cipher Padding Mode instance from it's enumeration name.
/// </summary>
class PaddingFromName
{
public:
	/// <summary>
	/// Get a Padding Mode by name
	/// </summary>
	/// 
	/// <param name="PaddingType">The padding enumeration name</param>
	/// 
	/// <returns>An initialized padding mode</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::Padding::IPadding* GetInstance(CEX::Enumeration::PaddingModes PaddingType);
};

NAMESPACE_HELPEREND
#endif