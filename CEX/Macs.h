#ifndef CEX_MACS_H
#define CEX_MACS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Message Authentication Code generator enumeration names
/// </summary>
enum class Macs : byte
{
	/// <summary>
	/// No MAC is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using AES
	/// </summary>
	CMAC = 1,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and HKDF-256
	/// </summary>
	CMACRHXH256= 2,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and HKDF-512
	/// </summary>
	CMACRHXH512 = 3,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-256
	/// </summary>
	CMACRHXS256 = 4,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-512
	/// </summary>
	CMACRHXS512 = 5,
	/// <summary>
	/// The GMAC authentication code generator using AES
	/// </summary>
	GMAC = 6,
	/// <summary>
	/// The GMAC authentication code generator using RHX and HKDF(HMAC(SHA2-256))
	/// </summary>
	GMACRHXH256 = 7,
	/// <summary>
	/// The GMAC authentication code generator using RHX and HKDF(HMAC(SHA2-512))
	/// </summary>
	GMACRHXH512 = 8,
	/// <summary>
	/// The GMAC authentication code generator using RHX and cSHAKE-256
	/// </summary>
	GMACRHXS256 = 9,
	/// <summary>
	/// The GMAC authentication code generator using RHX and cSHAKE-512
	/// </summary>
	GMACRHXS512 = 10,
	/// <summary>
	/// A Hash based Message Authentication Code generator using SHA2256
	/// </summary>
	HMACSHA2256 = 11,
	/// <summary>
	/// A Hash based Message Authentication Code generator using SHA2512
	/// </summary>
	HMACSHA2512 = 12,
	/// <summary>
	/// The Keccak based Parallel Authentication Code generator using Keccak-256
	/// </summary>
	KPA128 = 13,
	/// <summary>
	/// The Keccak based Parallel Authentication Code generator using Keccak-256
	/// </summary>
	KPA256 = 14,
	/// <summary>
	/// The Keccak based Parallel Authentication Code generator Keccak-512
	/// </summary>
	KPA512 = 15,
	/// <summary>
	/// The Keccak based Message Authentication Code generator using Keccak-128
	/// </summary>
	KMAC128 = 16,
	/// <summary>
	/// The Keccak based Message Authentication Code generator using Keccak-256
	/// </summary>
	KMAC256 = 17,
	/// <summary>
	/// The Keccak based Message Authentication Code generator Keccak-512
	/// </summary>
	KMAC512 = 18,
	/// <summary>
	/// The Keccak based Message Authentication Code generator Keccak-1024
	/// </summary>
	KMAC1024 = 19,
	/// <summary>
	/// The Poly1305 Message Authentication Code generator
	/// </summary>
	Poly1305 = 20
};

class MacConvert
{
public:

	/// <summary>
	/// Derive the Macs formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The Macs enumeration member</param>
	///
	/// <returns>The matching Macs string name</returns>
	static std::string ToName(Macs Enumeral);

	/// <summary>
	/// Derive the Macs enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The Macs string name</param>
	///
	/// <returns>The matching Macs enumeration type name</returns>
	static Macs FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
