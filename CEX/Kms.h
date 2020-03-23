#ifndef CEX_KMS_H
#define CEX_KMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Key Management Systems enumeration names
/// </summary>
enum class Kms : byte
{
	/// <summary>
	/// No Key Management System is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-128)
	/// </summary>
	HKDS128 = 1,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-256)
	/// </summary>
	HKDS256 = 2,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-512)
	/// </summary>
	HKDS512 = 3,
};

class KmsConvert
{
public:

	/// <summary>
	/// Derive the KMS formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The KMS enumeration member</param>
	///
	/// <returns>The matching KMS string name</returns>
	static std::string ToName(Kms Enumeral);

	/// <summary>
	/// Derive the KMS enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The KMS string name</param>
	///
	/// <returns>The matching KMS enumeration type name</returns>
	static Kms FromName(std::string &Name);
};
NAMESPACE_ENUMERATIONEND
#endif
