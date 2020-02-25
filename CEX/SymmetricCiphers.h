#ifndef CEX_SYMMETRICENGINES_H
#define CEX_SYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric encryption ciphers enumeration names
/// </summary>
enum class SymmetricCiphers : byte
{
	/// <summary>
	/// No symmetric cipher is specified
	/// </summary>
	None = 0,

	//~~~ Symmetric Block Cipher Variants~~//

	/// <summary>
	/// An implementation of the AES Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	AES = 1,
	/// <summary>
	/// An implementation of the Serpent Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	Serpent = 2,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(HMAC-SHA2-256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH256 = 39,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(HMAC-SHA2-512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH512 = 40,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS256 = 41,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS512 = 42,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS1024 = 43,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(HMAC-SHA2-256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH256 = 45,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(HMAC-SHA2-512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH512 = 46,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS256 = 47,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS512 = 48,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS1024 = 49,

	//~~~ ChaCha Stream-cipher Extended Variants~~//

	/// <summary>
	/// A standard implementation of the ChaChaPoly20 stream-cipher, this variant uses 20 rounds and has no athentication.
	/// <para>A standard ChaChaPoly20 stream-cipher implementation: uses a 512-bit block and a 256-bit key, and 8-byte nonce</para>
	/// </summary>
	CSX256 = 96,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with HMAC-SHA2-256
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20H256 = 97,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with HMAC-SHA2-512
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20H512 = 98,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC-256
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20K256 = 99,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC-512
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20K512 = 100,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with Poly1305
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20P256 = 101,

	/// <summary>
	/// A extended implementation of the ChaCha stream-cipher, this variant uses 80 rounds and has no athentication.
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSX512 = 102,
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with HMAC-SHA2-256
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80H256 = 103,
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with HMAC-SHA2-512
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80H512 = 104,
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with KMAC-256
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80K256 = 105,
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with KMAC-512
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80K512 = 106,
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with Poly1305
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80P256 = 107,

	//~~~ Rijndael-256 Extended Cipher Stream Variants~~//

	/// <summary>
	/// The Rijndael wide-block based authenticated stream cipher.
	/// <para>A Rijndael Extended cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes</para>
	/// </summary>
	RCS = 160,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using GMAC-RHX-256 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSG256 = 161,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using GMAC-RHX-512 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSG512 = 162,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using HMAC-SHA2-256 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSH256 = 163,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using HMAC-SHA2-512 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSH512 = 164,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-256 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK256 = 165,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-512 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK512 = 166,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-1024 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK1024 = 167,
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using Poly1305 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSP256 = 168,

	//~~~ Threefish Stream-cipher Extended Variants~~//

	/// <summary>
	/// A standard implementation of the Threefish-256 stream-cipher, this variant uses 72 rounds and has no athentication.
	/// <para>A Threefish-256 stream-cipher: uses a 256-bit block a 256-bit key size</para>
	/// </summary>
	TSX256 = 128,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with HMAC-SHA2-256
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72H256 = 129,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with HMAC-SHA2-512
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72H512 = 130,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC-256.
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72K256 = 131,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC-512.
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72K512 = 132,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with Poly1305.
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72P256 = 133,

	/// <summary>
	/// The Threefish 512-bit stream cipher, this variant uses 96 rounds and has no athentication.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSX512 = 134,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with HMAC-SHA2-256.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96H256 = 135,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with HMAC-SHA2-512.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96H512 = 136,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC-256.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96K256 = 137,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC-512.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96K512 = 138,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with Poly1305.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96P256 = 139,

	/// <summary>
	/// The Threefish 1024-bit stream cipher, this variant uses 120 rounds and has no athentication.
	/// <para>Extended cipher implementation: uses a 1024-bit block and a 1024-bit key size</para>
	/// </summary>
	TSX1024 = 140,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with HMAC-SHA2-256.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120H256 = 141,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with HMAC-SHA2-512.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120H512 = 142,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC-256.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120K256 = 143,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC-512.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120K512 = 144,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC-1024.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120K1024 = 145,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with Poly1305.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120P256 = 146
};

class SymmetricCipherConvert
{
public:

	/// <summary>
	/// Derive the SymmetricCiphers formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SymmetricCiphers enumeration member</param>
	///
	/// <returns>The matching SymmetricCiphers string name</returns>
	static std::string ToName(SymmetricCiphers Enumeral);

	/// <summary>
	/// Derive the SymmetricCiphers enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SymmetricCiphers string name</param>
	///
	/// <returns>The matching SymmetricCiphers enumeration type name</returns>
	static SymmetricCiphers FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
