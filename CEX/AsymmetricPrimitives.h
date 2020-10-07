#ifndef CEX_ASYMMETRICPRIMITIVES_H
#define CEX_ASYMMETRICPRIMITIVES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher and signature-scheme enumeration names
/// </summary>
enum class AsymmetricPrimitives : byte
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Elliptic ACurve Diffie Hellman cipher implementation
	/// </summary>
	ECDH = 1,
	/// <summary>
	/// A Module-LWE cipher implementation
	/// </summary>
	Kyber = 2,
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = 3,
	/// <summary>
	/// An NTRUPrime cipher implementation
	/// </summary>
	NTRUPrime = 4,
	/// <summary>
	/// The Dilithium asymmetric signature scheme
	/// </summary>
	Dilithium = 5,
	/// <summary>
	/// An Elliptic Curve Digital Signature Algorithm signature scheme
	/// </summary>
	ECDSA = 6,
	/// <summary>
	/// A Rainbow multivariate asymmetric signature scheme
	/// </summary>
	Rainbow = 7,
	/// <summary>
	/// A Ring-LWE cipher implementation
	/// </summary>
	NewHope = 8,
	/// <summary>
	/// The SphincsPlus asymmetric signature scheme
	/// </summary>
	SphincsPlus = 9,
	/// <summary>
	/// The eXtended Merkle Signature Scheme
	/// </summary>
	XMSS = 10,
	/// <summary>
	/// The eXtended Merkle Signature Scheme Multi-Tree
	/// </summary>
	XMSSMT = 11
};

class AsymmetricPrimitiveConvert
{
public:

	/// <summary>
	/// Derive the AsymmetricPrimitives formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AsymmetricPrimitives enumeration member</param>
	///
	/// <returns>The matching AsymmetricPrimitives string name</returns>
	static std::string ToName(AsymmetricPrimitives Enumeral);

	/// <summary>
	/// Derive the AsymmetricPrimitives enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AsymmetricPrimitives string name</param>
	///
	/// <returns>The matching AsymmetricPrimitives enumeration type name</returns>
	static AsymmetricPrimitives FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif



