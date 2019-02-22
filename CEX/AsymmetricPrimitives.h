#ifndef CEX_ASYMMETRICPRIMITIVES_H
#define CEX_ASYMMETRICPRIMITIVES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enumeration names
/// </summary>
enum class AsymmetricPrimitives : byte
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = 1,
	/// <summary>
	/// A Module-LWE cipher implementation
	/// </summary>
	ModuleLWE = 2,
	/// <summary>
	/// An NTRU cipher implementation
	/// </summary>
	NTRU = 3,
	/// <summary>
	/// The Dilithium asymmetric signature scheme
	/// </summary>
	Dilithium = 4,
	/// <summary>
	/// A Ring-LWE cipher implementation
	/// </summary>
	RingLWE = 5,
	/// <summary>
	/// The Sphincs asymmetric signature scheme
	/// </summary>
	Sphincs = 6
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



