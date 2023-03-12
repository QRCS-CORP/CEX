#ifndef CEX_PRNGS_H
#define CEX_PRNGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generators enumeration names
/// </summary>
enum class Prngs : uint8_t
{
	/// <summary>
	/// No prng is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator using a wide-block Rijndael
	/// </summary>
	BCR = 1,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-256
	/// </summary>
	CSR = 6,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-512
	/// </summary>
	CSRC512 = 7,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-1024
	/// </summary>
	CSRC1024 = 8,
	/// <summary>
	/// An HMAC based random number generator using SHA2256
	/// </summary>
	HCR = 9,
	/// <summary>
	/// An HMAC based random number generator using SHA2512
	/// </summary>
	HCRS512 = 10
};

class PrngConvert
{
public:

	/// <summary>
	/// Derive the Prngs formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The Prngs enumeration member</param>
	///
	/// <returns>The matching Prngs string name</returns>
	static std::string ToName(Prngs Enumeral);

	/// <summary>
	/// Derive the Prngs enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The Prngs string name</param>
	///
	/// <returns>The matching Prngs enumeration type name</returns>
	static Prngs FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
