#ifndef _CEX_KDFFROMNAME_H
#define _CEX_KDFFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "Digests.h"
#include "IKdf.h"
#include "Kdfs.h"

NAMESPACE_HELPER

using Kdf::IKdf;
using Enumeration::Digests;
using Enumeration::Kdfs;

/// <summary>
/// Get an uninitialized Key Derivation Function from a type name.
/// <para>The KDFs Initialize function must be called before Generate can be called.<para>
/// </summary>
class KdfFromName
{
public:
	/// <summary>
	/// Instantiate an uninitialized KDF generator from its enunmeration type name
	/// </summary>
	/// 
	/// <param name="KdfType">The Kdf generators type name</param>
	/// <param name="DigestType">The Kdf hash functions type name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Kdf or Digest type is not supported</exception>
	static IKdf* GetInstance(Kdfs KdfType, Digests DigestType);
};

NAMESPACE_HELPEREND
#endif