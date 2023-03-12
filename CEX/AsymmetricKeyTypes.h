#ifndef CEX_ASYMMETRICKEYTYPE_H
#define CEX_ASYMMETRICKEYTYPE_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric key type
/// </summary>
enum class AsymmetricKeyTypes : uint8_t
{
	/// <summary>
	/// No key type is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A cipher private key
	/// </summary>
	CipherPrivateKey = 1,
	/// <summary>
	/// A cipher public key
	/// </summary>
	CipherPublicKey = 2,
	/// <summary>
	/// A signature private key
	/// </summary>
	SignaturePrivateKey = 3,
	/// <summary>
	/// A signature public key
	/// </summary>
	SignaturePublicKey = 4
};

NAMESPACE_ENUMERATIONEND
#endif
