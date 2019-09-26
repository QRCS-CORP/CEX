#ifndef CEX_ASYMMETRICSIGNERFROMNAME_H
#define CEX_ASYMMETRICSIGNERFROMNAME_H

#include "CexDomain.h"
#include "AsymmetricSigners.h"
#include "AsymmetricParameters.h"
#include "CryptoException.h"
#include "IAsymmetricSigner.h"

NAMESPACE_HELPER

using Enumeration::AsymmetricSigners;
using Enumeration::AsymmetricParameters;
using Exception::CryptoException;
using Asymmetric::Sign::IAsymmetricSigner;

/// <summary>
/// Get an initialized asymmetric signature scheme instance from it's enumeration name.
/// <para>Use the Parameter field to set the signature scheme instance parameters.</para>
/// </summary>
class AsymmetricSignerFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get an initialized asymmetric signature scheme instance by enumeration name
	/// </summary>
	/// 
	/// <param name="CipherType">The asymmetric signature schemes enumeration name</param>
	/// <param name="Parameters">The asymmetric signature schemes parameters enumeration name</param>
	/// 
	/// <returns>An initialized asymmetric cipher instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the signature scheme or parameters are not supported</exception>
	static IAsymmetricSigner* GetInstance(AsymmetricSigners SignerType, AsymmetricParameters Parameters);
};

NAMESPACE_HELPEREND
#endif
