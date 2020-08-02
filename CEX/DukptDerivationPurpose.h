#ifndef CEX_DUKPTDERIVATIONPURPOSE_H
#define CEX_DUKPTDERIVATIONPURPOSE_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// B.3.1 Enumerations; the derivation purpose modes, from ANSI X9.24-3 2017 DUKPT
/// </summary>
enum class DukptDerivationPurpose : byte
{
    /// <summary>
    /// Initial key generation
    /// </summary>
    InitialKey = 0x00,
    /// <summary>
    /// Key derivation or working key
    /// </summary>
    DerivationOrWorkingKey = 0x01
};

NAMESPACE_ENUMERATIONEND
#endif
