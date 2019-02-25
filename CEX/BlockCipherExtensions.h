#ifndef CEX_BLOCKCIPHEREXTENSIONS_H
#define CEX_BLOCKCIPHEREXTENSIONS_H

#include "CexDomain.h"
#include "Kdfs.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Select the symmetric block cipher round-key expansion engines
/// </summary>
enum class BlockCipherExtensions : byte
{
	/// <summary>
	/// Use the standard form of the block cipher
	/// </summary>
	None = 0,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-256)
	/// </summary>
	HKDF256 = static_cast<byte>(Kdfs::HKDF256),
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-512)
	/// </summary>
	HKDF512 = static_cast<byte>(Kdfs::HKDF512),
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = static_cast<byte>(Kdfs::SHAKE256),
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = static_cast<byte>(Kdfs::SHAKE512),
	/// <summary>
	/// An implementation of the SHAKE-1024 XOF function -experimental
	/// </summary>
	SHAKE1024 = static_cast<byte>(Kdfs::SHAKE1024),
	/// <summary>
	/// User defined derivation function
	/// </summary>
	Custom = 99
};

NAMESPACE_ENUMERATIONEND
#endif
