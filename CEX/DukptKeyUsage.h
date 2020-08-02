#ifndef CEX_DUKPTKEYUSAGE_H
#define CEX_DUKPTKEYUSAGE_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// B.3.1 Enumerations; the key usage modes, from ANSI X9.24-3 2017 DUKPT
/// </summary>
enum class DukptKeyUsage : ushort
{
    /// <summary>
    /// No usage-type is specified
    /// </summary>
    None = 0,
    /// <summary>
    /// Create an encryption key
    /// </summary>
    KeyEncryptionKey = 0x0002,
    /// <summary>
    /// Initial key derivation
    /// </summary>
    KeyDerivationInitialKey = 0x0009,
    /// <summary>
    /// Encrypt a PIN message
    /// </summary>
    PINEncryption = 0x1000,
    /// <summary>
    /// MAC code generation
    /// </summary>
    MessageAuthenticationGeneration = 0x2000,
    /// <summary>
    /// MAC code verification
    /// </summary>
    MessageAuthenticationVerification = 0x2001,
    /// <summary>
    /// Two-way message authentication
    /// </summary>
    MessageAuthenticationBothWays = 0x2002,
    /// <summary>
    /// Data encryption
    /// </summary>
    DataEncryptionEncrypt = 0x3000,
    /// <summary>
    /// Data decryption
    /// </summary>
    DataEncryptionDecrypt = 0x3001,
    /// <summary>
    /// Two-way data encryption
    /// </summary>
    DataEncryptionBothWays = 0x3002,
    /// <summary>
    /// Key derivation
    /// </summary>
    KeyDerivation = 0x8000
};

NAMESPACE_ENUMERATIONEND
#endif
