#ifndef CEX_ASYMMETRICCIPHERS_H
#define CEX_ASYMMETRICCIPHERS_H

#include "CexDomain.h"
#include "AsymmetricPrimitives.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher and signature-scheme enumeration names
/// </summary>
enum class AsymmetricCiphers : uint8_t
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Module-LWE cipher implementation
	/// </summary>
	Kyber = static_cast<uint8_t>(AsymmetricPrimitives::Kyber),
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = static_cast<uint8_t>(AsymmetricPrimitives::McEliece),
	/// <summary>
	/// An elliptic curve cipher implementation
	/// </summary>
	ECDH = static_cast<uint8_t>(AsymmetricPrimitives::ECDH),
};

class AsymmetricCipherConvert
{
public:

	/// <summary>
	/// Derive the AsymmetricCipher formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AsymmetricCipher enumeration member</param>
	///
	/// <returns>The matching AsymmetricCipher string name</returns>
	static std::string ToName(AsymmetricCiphers Enumeral);

	/// <summary>
	/// Derive the AsymmetricCipher enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AsymmetricCipher string name</param>
	///
	/// <returns>The matching AsymmetricCipher enumeration type name</returns>
	static AsymmetricCiphers FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif



