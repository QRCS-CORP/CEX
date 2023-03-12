#ifndef CEX_BLOCKCIPHEREXTENSIONS_H
#define CEX_BLOCKCIPHEREXTENSIONS_H

#include "CexDomain.h"
#include "Kdfs.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Select the symmetric block cipher round-key expansion engines
/// </summary>
enum class BlockCipherExtensions : uint8_t
{
	/// <summary>
	/// Use the standard form of the block cipher
	/// </summary>
	None = 0,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-256)
	/// </summary>
	HKDF256 = static_cast<uint8_t>(Kdfs::HKDF256),
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-512)
	/// </summary>
	HKDF512 = static_cast<uint8_t>(Kdfs::HKDF512),
	/// <summary>
	/// An implementation of the SHAKE-128 XOF function
	/// </summary>
	SHAKE128 = static_cast<uint8_t>(Kdfs::SHAKE128),
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = static_cast<uint8_t>(Kdfs::SHAKE256),
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = static_cast<uint8_t>(Kdfs::SHAKE512)
};

NAMESPACE_ENUMERATIONEND
#endif
