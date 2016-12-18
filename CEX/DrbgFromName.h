#ifndef _CEX_DRBGFROMNAME_H
#define _CEX_DRBGFROMNAME_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "CryptoException.h"
#include "Digests.h"
#include "IDrbg.h"
#include "Drbgs.h"
#include "Providers.h"

NAMESPACE_HELPER

using Enumeration::BlockCiphers;
using Enumeration::Digests;
using Enumeration::Drbgs;
using Enumeration::Providers;
using Drbg::IDrbg;

/// <summary>
/// Get an uninitialized Deterministic Random Bit Generator from a type name.
/// <para>The DRBGs Initialize function must be called before a generate function can be called.<para>
/// </summary>
class DrbgFromName
{
public:

	/// <summary>
	/// Instantiate an uninitialized DRBG generator from its enunmeration type name.
	/// <para>Initializes the generator with the default parameters.</para>
	/// </summary>
	/// 
	/// <param name="DrbgType">The DRBG generators enumeration name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Kdf or Digest type is not supported</exception>
	static IDrbg* GetInstance(Drbgs DrbgType);

	/// <summary>
	/// Instantiate an uninitialized DRBG generator with options
	/// </summary>
	/// 
	/// <param name="DrbgType">The DRBG generators enumeration name</param>
	/// <param name="DigestType">The primary engine with HMG and DCG, or the key expansion function in CMG</param>
	/// <param name="ProviderType">The entropy providers enumeration name</param>
	/// 
	/// <returns>An uninitialized DRBG generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the DRBG or Digest type is not supported</exception>
	static IDrbg* GetInstance(Drbgs DrbgType, Digests DigestType, Providers ProviderType);
};

NAMESPACE_HELPEREND
#endif