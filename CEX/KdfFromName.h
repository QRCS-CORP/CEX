#ifndef CEX_KDFFROMNAME_H
#define CEX_KDFFROMNAME_H

#include "CexDomain.h"
#include "BlockCipherExtensions.h"
#include "CryptoException.h"
#include "IKdf.h"
#include "KdfDigests.h"
#include "Kdfs.h"

NAMESPACE_HELPER

using Enumeration::BlockCipherExtensions;
using Exception::CryptoException;
using Kdf::IKdf;
using Enumeration::KdfDigests;
using Enumeration::Kdfs;

/// <summary>
/// Get an uninitialized Key Derivation Function from a type name.
/// <para>The KDFs Initialize function must be called before Generate can be called.</para>
/// </summary>
class KdfFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Instantiate an uninitialized KDF generator from its enumeration type name
	/// </summary>
	/// 
	/// <param name="KdfType">The Kdf generators type name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Kdf type is not supported</exception>
	static IKdf* GetInstance(Kdfs KdfType);

	/// <summary>
	/// Instantiate an uninitialized KDF generator from its enumeration type name
	/// </summary>
	/// 
	/// <param name="ExtensionType">The Kdf generators type name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the block cipher extension type is not supported</exception>
	static IKdf* GetInstance(BlockCipherExtensions ExtensionType);

	/// <summary>
	/// Instantiate an uninitialized KDF generator from its enumeration type name
	/// </summary>
	/// 
	/// <param name="DigestType">The Kdf digests type name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the block cipher extension type is not supported</exception>
	static IKdf* GetInstance(KdfDigests DigestType);
};

NAMESPACE_HELPEREND
#endif
