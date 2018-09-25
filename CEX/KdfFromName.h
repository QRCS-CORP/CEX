#ifndef CEX_KDFFROMNAME_H
#define CEX_KDFFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IKdf.h"
#include "Kdfs.h"

NAMESPACE_HELPER

using Exception::CryptoException;
using Kdf::IKdf;
using Enumeration::Kdfs;

/// <summary>
/// Get an uninitialized Key Derivation Function from a type name.
/// <para>The KDFs Initialize function must be called before Generate can be called.</para>
/// </summary>
class KdfFromName
{
public:

	/// <summary>
	/// Instantiate an uninitialized KDF generator from its enumeration type name
	/// </summary>
	/// 
	/// <param name="KdfType">The Kdf generators type name</param>
	/// 
	/// <returns>An uninitialized Kdf generator</returns>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the Kdf is not supported</exception>
	static IKdf* GetInstance(Kdfs KdfType);
};

NAMESPACE_HELPEREND
#endif
