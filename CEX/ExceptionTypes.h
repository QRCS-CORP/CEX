#ifndef CEX_EXCEPTIONTYPES_H
#define CEX_EXCEPTIONTYPES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric AEAD cipher mode enumeration names
/// </summary>
enum class ExceptionTypes : byte
{
	/// <summary>
	/// No exception type is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// Asymmetric cipher and signature scheme exception
	/// </summary>
	CryptoAsymmetricException = 1,
	/// <summary>
	/// Asymmetric cipher/signature, and AEAD mode authentication failure exception
	/// </summary>
	CryptoAuthenticationFailure = 2,
	/// <summary>
	/// Symmetric cipher-mode operations exception
	/// </summary>
	CryptoCipherModeException = 3,
	/// <summary>
	/// Cryptographic digest exception
	/// </summary>
	CryptoDigestException = 4,
	/// <summary>
	/// Base cryptographic exception
	/// </summary>
	CryptoException = 5,
	/// <summary>
	/// Cryptographic pseudo-random generator exception
	/// </summary>
	CryptoGeneratorException = 6,
	/// <summary>
	/// Key derivation function exception
	/// </summary>
	CryptoKdfException = 7,
	/// <summary>
	/// Message authentication code generator exception
	/// </summary>
	CryptoMacException = 8,
	/// <summary>
	/// Symmetric block cipher padding exception
	/// </summary>
	CryptoPaddingException = 9,
	/// <summary>
	/// Cryptographic data processing exception
	/// </summary>
	CryptoProcessingException = 10,
	/// <summary>
	/// Cryptographic pseudo random number generator exception
	/// </summary>
	CryptoRandomException = 11,
	/// <summary>
	/// Symmetric cipher operationas exception
	/// </summary>
	CryptoSymmetricCipherException = 12
};

NAMESPACE_ENUMERATIONEND
#endif
