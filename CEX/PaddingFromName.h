#ifndef CEX_PADDINGFROMNAME_H
#define CEX_PADDINGFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IPadding.h"

NAMESPACE_HELPER

using Cipher::Symmetric::Block::Padding::IPadding;
using Enumeration::PaddingModes;

/// <summary>
/// Get a Cipher Padding Mode instance from it's enumeration name.
/// </summary>
class PaddingFromName
{
public:
	/// <summary>
	/// Get a Padding Mode by name
	/// </summary>
	/// 
	/// <param name="PaddingType">The padding mode enumeration name</param>
	/// 
	/// <returns>A padding mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IPadding* GetInstance(PaddingModes PaddingType);
};

NAMESPACE_HELPEREND
#endif