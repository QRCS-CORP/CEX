#ifndef CEX_SYMMETRICENGINES_H
#define CEX_SYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric encryption ciphers enumeration names
/// </summary>
enum class SymmetricEngines : byte
{
	/// <summary>
	/// No symmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An AES-NI block cipher implementation with optional HKDF key expansion
	/// </summary>
	AHX = 1,
	/// <summary>
	/// An implementation based on the Rijndael block cipher with optional HKDF key expansion
	/// </summary>
	RHX = 2,
	/// <summary>
	/// The Serpent block cipher with optional HKDF key expansion
	/// </summary>
	SHX = 4,
	/// <summary>
	/// A Twofish Block Cipher with optional HKDF key expansion
	/// </summary>
	THX = 8,
	/// <summary>
	/// An implementation of the ChaCha stream cipher
	/// </summary>
	ChaCha20 = 16,
	/// <summary>
	/// An implementation of the Salsa stream cipher
	/// </summary>
	Salsa = 32
};

NAMESPACE_ENUMERATIONEND
#endif