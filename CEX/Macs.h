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
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-256
	/// </summary>
	CMACAHXS256= 2,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-512
	/// </summary>
	CMACAHXS512 = 3,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using AES
	/// </summary>
	GMAC = 4,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-256
	/// </summary>
	GMACAHXS256 = 5,
	/// <summary>
	/// A Cipher based Message Authentication Code generator using RHX and cSHAKE-512
	/// </summary>
	GMACAHXS512 = 6,
	/// <summary>
	/// A Hash based Message Authentication Code generator using SHA256
	/// </summary>
	HMACSHA256 = 7,
	/// <summary>
	/// A Hash based Message Authentication Code generator using SHA512
	/// </summary>
	HMACSHA512 = 8,
	/// <summary>
	/// The Keccak based Message Authentication Code generator using Keccak-256
	/// </summary>
	KMAC128 = 9,
	/// <summary>
	/// The Keccak based Message Authentication Code generator using Keccak-256
	/// </summary>
	KMAC256 = 10,
	/// <summary>
	/// The Keccak based Message Authentication Code generator Keccak-512
	/// </summary>
	KMAC512 = 11,
	/// <summary>
	/// The Keccak based Message Authentication Code generator Keccak-1024
	/// </summary>
	KMAC1024 = 12,
	/// <summary>
	/// The Poly1305 Message Authentication Code generator
	/// </summary>
	Poly1305 = 13
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
