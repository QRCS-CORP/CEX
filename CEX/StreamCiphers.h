#ifndef _CEX_STREAMCIPHERS_H
#define _CEX_STREAMCIPHERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Stream cipher enumeration names
/// </summary>
enum class StreamCiphers : byte
{
	/// <summary>
	/// No stream cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation of the ChaCha Stream Cipher
	/// </summary>
	ChaCha20 = 16,
	/// <summary>
	/// A Salsa20 Stream Cipher
	/// </summary>
	Salsa20 = 32
};

NAMESPACE_ENUMERATIONEND
#endif