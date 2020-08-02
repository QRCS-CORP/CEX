#ifndef CEX_DIGESTS_H
#define CEX_DIGESTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic hash functions enumeration names
/// </summary>
enum class Digests : byte
{

	/// <summary>
	/// No hash digest is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Blake2S digest with a 256 bit return size
	/// </summary>
	Blake256 = 1,
	/// <summary>
	/// The Blake2B digest with a 512 bit return size
	/// </summary>
	Blake512 = 2,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 256 bit return size
	/// </summary>
	SHA3256 = 3,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 512 bit return size
	/// </summary>
	SHA3512 = 4,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 1024 bit return size
	/// </summary>
	SHA31024 = 5,
	/// <summary>
	///The SHA-2 digest with a 256 bit return size
	/// </summary>
	SHA2256 = 6,
	/// <summary>
	/// The SHA-2 digest with a 512 bit return size
	/// </summary>
	SHA2512 = 7,
	/// <summary>
	/// The SHAKE-128 digest with a 128 bit return size
	/// </summary>
	SHAKE128 = 9,
	/// <summary>
	/// The SHAKE-256 digest with a 256 bit return size
	/// </summary>
	SHAKE256 = 10,
	/// <summary>
	/// The SHAKE-512 digest with a 512 bit return size
	/// </summary>
	SHAKE512 = 11,
	/// <summary>
	/// The SHAKE-1024 digest with a 1024 bit return size
	/// </summary>
	SHAKE1024 = 12,
	/// <summary>
	/// The Skein digest with a 256 bit return size
	/// </summary>
	Skein256 = 13,
	/// <summary>
	/// The Skein digest with a 512 bit return size
	/// </summary>
	Skein512 = 14,
	/// <summary>
	/// The Skein digest with a 1024 bit return size
	/// </summary>
	Skein1024 = 15
};

class DigestConvert
{
public:

	/// <summary>
	/// Derive the Digests formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The Digests enumeration member</param>
	///
	/// <returns>The matching Digests string name</returns>
	static std::string ToName(Digests Enumeral);

	/// <summary>
	/// Derive the Digests enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The Digests string name</param>
	///
	/// <returns>The matching Digests enumeration type name</returns>
	static Digests FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
