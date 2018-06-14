#ifndef CEX_KDFS_H
#define CEX_KDFS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Key Derivation Functions enumeration names
/// </summary>
enum class Kdfs : byte
{
	/// <summary>
	/// No kdf is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-256)
	/// </summary>
	HKDF256 = 1,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-512)
	/// </summary>
	HKDF512 = 2,
	/// <summary>
	/// An implementation of the Hash based Key Derivation Function: KDF2(SHA2-256)
	/// </summary>
	KDF2256 = 3,
	/// <summary>
	/// An implementation of the Hash based Key Derivation Function: KDF2(SHA2-512)
	/// </summary>
	KDF2512 = 4,
	/// <summary>
	/// An implementation of a Passphrase Based KDF: PBKDF2(SHA2-256)
	/// </summary>
	PBKDF2256 = 5,
	/// <summary>
	/// An implementation of a Passphrase Based KDF: PBKDF2(SHA2-512)
	/// </summary>
	PBKDF2512 = 6,
	/// <summary>
	/// An implementation of the SCRYPT(SHA2-256)
	/// </summary>
	SCRYPT256 = 7,
	/// <summary>
	/// An implementation of the SCRYPT(SHA2-512)
	/// </summary>
	SCRYPT512 = 8,
	/// <summary>
	/// An implementation of the SHAKE-128 XOF function
	/// </summary>
	SHAKE128 = 9,
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = 10,
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = 11,
	/// <summary>
	/// An implementation of the SHAKE-1024 XOF function
	/// </summary>
	SHAKE1024 = 12
};

NAMESPACE_ENUMERATIONEND
#endif
