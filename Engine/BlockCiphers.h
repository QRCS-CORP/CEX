#ifndef _CEXENGINE_BLOCKCIPHERS_H
#define _CEXENGINE_BLOCKCIPHERS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Block Ciphers
/// </summary>
enum class BlockCiphers : unsigned int
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
	THX = 32
};

NAMESPACE_ENUMERATIONEND
#endif

