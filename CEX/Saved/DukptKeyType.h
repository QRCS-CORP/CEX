#ifndef CEX_DUKPTKEYTYPE_H
#define CEX_DUKPTKEYTYPE_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// B.3.1 Enumerations; the cipher-type key modes, from ANSI X9.24-3 2017 DUKPT
/// </summary>
enum class DukptKeyType : byte
{
    /// <summary>
    /// No cipher is specified
    /// </summary>
    None = 0x00,
    /// <summary>
    /// AES-128 cipher key
    /// </summary>
    AES128 = 0x02,
    /// <summary>
    /// AES-192 cipher key
    /// </summary>
    AES192 = 0x03,
    /// <summary>
    /// AES-256 cipher key
    /// </summary>
    AES256 = 0x04
};

NAMESPACE_ENUMERATIONEND
#endif
