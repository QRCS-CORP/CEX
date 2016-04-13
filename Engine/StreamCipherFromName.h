#ifndef _CEXENGINE_STREAMCIPHERFROMNAME_H
#define _CEXENGINE_STREAMCIPHERFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IStreamCipher.h"

NAMESPACE_HELPER

/// <summary>
/// StreamCipherFromName: Get a Stream Cipher instance from it's enumeration name.
/// </summary>
class StreamCipherFromName
{
public:
	/// <summary>
	/// Get a stream cipher instance with specified initialization parameters
	/// </summary>
	/// 
	/// <param name="StreamCipherType">The stream cipher enumeration name</param>
	/// <param name="RoundCount">The number of cipher rounds</param>
	/// 
	/// <returns>An initialized stream cipher</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Stream::IStreamCipher* GetInstance(CEX::Enumeration::StreamCiphers StreamCipherType, uint RoundCount);
};

NAMESPACE_HELPEREND
#endif