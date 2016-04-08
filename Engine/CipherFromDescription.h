#ifndef _CEXENGINE_BLOCKCIPHERFROMDESCRIPTION_H
#define _CEXENGINE_BLOCKCIPHERFROMDESCRIPTION_H

#include "Common.h"
#include "CipherDescription.h"
#include "ICipherMode.h"

NAMESPACE_HELPER

/// <summary>
/// Get a symmetric cipher instance from it's description
/// </summary>
class CipherFromDescription
{
public:
	/// <summary>
	/// Get an uninitialized block cipher and mode from a description structure
	/// </summary>
	/// 
	/// <param name="Description">The structure describing the symmetric cipher</param>
	/// 
	/// <returns>An uninitialized symmetric cipher wrapped in a mode</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the cipher type is not supported</exception>
	static CEX::Cipher::Symmetric::Block::Mode::ICipherMode* GetInstance(CEX::Common::CipherDescription &Description);
};

NAMESPACE_HELPEREND
#endif