#ifndef CEX_KDFS_H
#define CEX_KDFS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Key Derivation Functions enumeration names.
/// <para>Note: SHAKE enumerals must coincide with ShakeModes/Digests enumeration members.</para>
/// </summary>
enum class Kdfs : byte
{
	/// <summary>
	/// No kdf is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF
	/// </summary>
	HKDF = 1,
	/// <summary>
	/// An implementation of the Hash based Key Derivation Function: KDF2
	/// </summary>
	KDF2 = 2,
	/// <summary>
	/// An implementation of a Passphrase Based KDF: PBKDF2
	/// </summary>
	PBKDF2 = 3,
	/// <summary>
	/// An implementation of the SCRYPT KDF
	/// </summary>
	SCRYPT = 4,
	/// <summary>
	/// An implementation of the SHAKE-128 XOF function
	/// </summary>
	SHAKE128 = 8,
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = 9,
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = 10,
	/// <summary>
	/// An implementation of the SHAKE-1024 XOF function
	/// </summary>
	SHAKE1024 = 11
};

NAMESPACE_ENUMERATIONEND
#endif
