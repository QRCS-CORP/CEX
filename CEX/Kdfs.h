#ifndef _CEX_KDFS_H
#define _CEX_KDFS_H

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
	PBKDF2 = 4,
	/// <summary>
	/// An implementation of the SCRYPT KDF
	/// </summary>
	SCRYPT = 8
};

NAMESPACE_ENUMERATIONEND
#endif