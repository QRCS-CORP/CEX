#ifndef CEX_KDFDIGESTS_H
#define CEX_KDFDIGESTS_H

#include "CexDomain.h"
#include "Digests.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Select the digest for a Key Derivation Function
/// </summary>
enum class KdfDigests : byte
{
	/// <summary>
	/// Use the standard form of the block cipher
	/// </summary>
	None = 0,
	/// <summary>
	///The SHA-2 digest with a 256 bit return size
	/// </summary>
	SHA2256 = static_cast<byte>(Digests::SHA2256),
	/// <summary>
	/// The SHA-2 digest with a 512 bit return size
	/// </summary>
	SHA2512 = static_cast<byte>(Digests::SHA2512),
	/// <summary>
	/// An implementation of the SHAKE-128 XOF function
	/// </summary>
	SHAKE128 = static_cast<byte>(Digests::SHAKE128),
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = static_cast<byte>(Digests::SHAKE256),
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = static_cast<byte>(Digests::SHAKE512),
	/// <summary>
	/// An implementation of the SHAKE-1024 XOF function -experimental
	/// </summary>
	SHAKE1024 = static_cast<byte>(Digests::SHAKE1024)
};

NAMESPACE_ENUMERATIONEND
#endif
