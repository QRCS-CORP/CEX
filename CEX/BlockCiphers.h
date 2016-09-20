#ifndef _CEXENGINE_BLOCKCIPHERS_H
#define _CEXENGINE_BLOCKCIPHERS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Block Ciphers
/// </summary>
enum class BlockCiphers : uint
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
	THX = 8
};

NAMESPACE_ENUMERATIONEND
#endif

