#ifndef CEX_STREAMCIPHERFROMNAME_H
#define CEX_STREAMCIPHERFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IStreamCipher.h"

NAMESPACE_HELPER

using Exception::CryptoException;
using Cipher::Stream::IStreamCipher;
using Enumeration::StreamCiphers;

/// <summary>
/// Get a Stream Cipher instance from it's enumeration name.
/// <para>The stream ciphers Initialize function must be called before it can be used.</para>
/// </summary>
class StreamCipherFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get a stream cipher instance with specified initialization parameters
	/// </summary>
	/// 
	/// <param name="StreamCipherType">The stream cipher enumeration name</param>
	/// 
	/// <returns>An uninitialized stream cipher</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the stream cipher type is not supported</exception>
	static IStreamCipher* GetInstance(StreamCiphers StreamCipherType);
};

NAMESPACE_HELPEREND
#endif
