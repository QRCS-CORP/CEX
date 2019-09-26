#ifndef CEX_ASYMMETRICSIGNERS_H
#define CEX_ASYMMETRICSIGNERS_H

#include "CexDomain.h"
#include "AsymmetricPrimitives.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric signature-scheme enumeration names
/// </summary>
enum class AsymmetricSigners : byte
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Dilithium asymmetric signature scheme
	/// </summary>
	Dilithium = static_cast<byte>(AsymmetricPrimitives::Dilithium),
	/// <summary>
	/// A Rainbow multivariate asymmetric signature scheme
	/// </summary>
	Rainbow = static_cast<byte>(AsymmetricPrimitives::Rainbow),
	/// <summary>
	/// The SphincsPlus asymmetric signature scheme
	/// </summary>
	SphincsPlus = static_cast<byte>(AsymmetricPrimitives::SphincsPlus),
	/// <summary>
	/// The eXtended Merkle Signature Scheme
	/// </summary>
	XMSS = static_cast<byte>(AsymmetricPrimitives::XMSS),
	/// <summary>
	/// The eXtended Merkle Signature Scheme Multi-Tree
	/// </summary>
	XMSSMT = static_cast<byte>(AsymmetricPrimitives::XMSSMT)
};

class AsymmetricSignerConvert
{
public:

	/// <summary>
	/// Derive the AsymmetricSigner formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AsymmetricSigner enumeration member</param>
	///
	/// <returns>The matching AsymmetricSigner string name</returns>
	static std::string ToName(AsymmetricSigners Enumeral);

	/// <summary>
	/// Derive the AsymmetricSigner enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AsymmetricSigner string name</param>
	///
	/// <returns>The matching AsymmetricSigner enumeration type name</returns>
	static AsymmetricSigners FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif



