#ifndef CEX_ASYMMETRICCIPHERFROMNAME_H
#define CEX_ASYMMETRICCIPHERFROMNAME_H

#include "CexDomain.h"
#include "AsymmetricCiphers.h"
#include "AsymmetricParameters.h"
#include "CryptoException.h"
#include "IAsymmetricCipher.h"

NAMESPACE_HELPER

using Enumeration::AsymmetricCiphers;
using Enumeration::AsymmetricParameters;
using Exception::CryptoException;
using Asymmetric::Encrypt::IAsymmetricCipher;

/// <summary>
/// Get an initialized asymmetric cipher instance from it's enumeration name.
/// <para>Use the Parameter field to set the ciphers instance parameters.</para>
/// </summary>
class AsymmetricCipherFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get an initialized asymmetric cipher instance by enumeration name
	/// </summary>
	/// 
	/// <param name="CipherType">The asymmetric ciphers enumeration name</param>
	/// <param name="Parameters">The asymmetric ciphers parameters enumeration name</param>
	/// 
	/// <returns>An initialized asymmetric cipher instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the cipher or parameters are not supported</exception>
	static IAsymmetricCipher* GetInstance(AsymmetricCiphers CipherType, AsymmetricParameters Parameters);
};

NAMESPACE_HELPEREND
#endif
