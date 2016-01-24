#ifndef _CEXENGINE_PADDINGFROMNAME_H
#define _CEXENGINE_PADDINGFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IPadding.h"
#include "PaddingModes.h"

NAMESPACE_HELPER

using CEX::Cipher::Symmetric::Block::Padding::IPadding;
using CEX::Enumeration::PaddingModes;
using CEX::Exception::CryptoException;

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
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static IPadding* GetInstance(PaddingModes PaddingType);
};

NAMESPACE_HELPEREND
#endif