#ifndef _CEXENGINE_SYMMETRICENGINES_H
#define _CEXENGINE_SYMMETRICENGINES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Symmetric Encryption Ciphers
/// </summary>
enum class SymmetricEngines : unsigned int
{
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
	/// </summary>
	RHX = 2,
	/// <summary>
	/// The Serpent Block Cipher Extended with an HKDF Key Schedule
	/// </summary>
	SHX = 8,
	/// <summary>
	/// A Twofish Block Cipher Extended with an HKDF Key Schedule
	/// </summary>
	THX = 32,
	/// <summary>
	/// An implementation of the ChaCha Stream Cipher
	/// </summary>
	ChaCha = 64,
	/// <summary>
	/// A Salsa20 Stream Cipher
	/// </summary>
	Salsa = 128,
};
NAMESPACE_ENUMERATIONEND

#endif