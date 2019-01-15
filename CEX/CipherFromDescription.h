#ifndef CEX_CIPHERFROMDESCRIPTION_H
#define CEX_CIPHERFROMDESCRIPTION_H

#include "CexDomain.h"
#include "CipherDescription.h"
#include "CryptoException.h"
#include "ICipherMode.h"

NAMESPACE_HELPER

using Processing::CipherDescription;
using Exception::CryptoException;
using Cipher::Block::Mode::ICipherMode;
using Enumeration::BlockCiphers;

/// <summary>
/// Get a symmetric cipher instance from it's description.
/// <para>The Cipher modes Initialize function must be called before it can be used.</para>
/// </summary>
class CipherFromDescription
{
public:

	/// <summary>
	/// Get an uninitialized block cipher and mode from a description structure
	/// </summary>
	/// 
	/// <param name="Description">The structure containing the symmetric cipher configuration</param>
	/// 
	/// <returns>An uninitialized symmetric cipher mode</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the cipher type is not supported</exception>
	static ICipherMode* GetInstance(CipherDescription &Description);
};

NAMESPACE_HELPEREND
#endif
