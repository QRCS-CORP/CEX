#ifndef _CEXENGINE_SYMMETRICENGINES_H
#define _CEXENGINE_SYMMETRICENGINES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Symmetric Encryption Ciphers
/// </summary>
enum class SymmetricEngines : uint
{
	/// <summary>
	/// An AES-NI implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
	/// </summary>
	AHX = 1,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
	/// </summary>
	RHX = 2,
	/// <summary>
	/// The Serpent Block Cipher Extended with an HKDF Key Schedule
	/// </summary>
	SHX = 4,
	/// <summary>
	/// A Twofish Block Cipher Extended with an HKDF Key Schedule
	/// </summary>
	THX = 8,
	/// <summary>
	/// An implementation of the ChaCha Stream Cipher
	/// </summary>
	ChaCha = 16,
	/// <summary>
	/// A Salsa20 Stream Cipher
	/// </summary>
	Salsa = 32
};

NAMESPACE_ENUMERATIONEND
#endif