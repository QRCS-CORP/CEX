#ifndef _CEXENGINE_STREAMCIPHERFROMNAME_H
#define _CEXENGINE_STREAMCIPHERFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IStreamCipher.h"
#include "StreamCiphers.h"

NAMESPACE_HELPER

using CEX::Cipher::Symmetric::Stream::IStreamCipher;
using CEX::Enumeration::StreamCiphers;
using CEX::Exception::CryptoException;

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
	/// <param name="EngineType">The stream cipher enumeration name</param>
	/// <param name="RoundCount">The number of cipher rounds</param>
	/// 
	/// <returns>An initialized stream cipher</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static IStreamCipher* GetInstance(StreamCiphers EngineType, int RoundCount);
};

NAMESPACE_HELPEREND
#endif