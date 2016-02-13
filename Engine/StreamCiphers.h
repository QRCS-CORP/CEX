#ifndef _CEXENGINE_STREAMCIPHERS_H
#define _CEXENGINE_STREAMCIPHERS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Stream Ciphers
/// </summary>
enum class StreamCiphers : uint
{
	/// <summary>
	/// An implementation of the ChaCha Stream Cipher
	/// </summary>
	ChaCha = 64,
	/// <summary>
	/// A Salsa20 Stream Cipher
	/// </summary>
	Salsa = 128
};

NAMESPACE_ENUMERATIONEND
#endif