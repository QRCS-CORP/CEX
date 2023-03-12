#ifndef CEX_THREEFISHMODES_H
#define CEX_THREEFISHMODES_H

#include "CexDomain.h"
#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Threefish stream cipher operation-modes enumeration names
/// </summary>
enum class ThreefishModes : uint8_t
{
	/// <summary>
	/// No Threefish mode has been selected
	/// </summary>
	None = 0,
	/// <summary>
	/// A standard implementation of the Threefish-256 stream-cipher, this variant uses 72 rounds and has no athentication.
	/// <para>A Threefish-256 stream-cipher: uses a 256-bit block a 256-bit key size</para>
	/// </summary>
	TSX256 = static_cast<uint8_t>(SymmetricCiphers::TSX256),
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC-256.
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72K256 = static_cast<uint8_t>(SymmetricCiphers::TSXR72K256),
	/// <summary>
	/// The Threefish 512-bit stream cipher, this variant uses 96 rounds and has no athentication.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSX512 = static_cast<uint8_t>(SymmetricCiphers::TSX512),
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC-512.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96K512 = static_cast<uint8_t>(SymmetricCiphers::TSXR96K512),
	/// <summary>
	/// The Threefish 1024-bit stream cipher, this variant uses 120 rounds and has no athentication.
	/// <para>Extended cipher implementation: uses a 1024-bit block and a 1024-bit key size</para>
	/// </summary>
	TSX1024 = static_cast<uint8_t>(SymmetricCiphers::TSX1024),
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC-1024.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120K512 = static_cast<uint8_t>(SymmetricCiphers::TSXR120K512)
};

class ThreefishModeConvert
{
public:

	/// <summary>
	/// Derive the ThreefishModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The ThreefishModes enumeration member</param>
	///
	/// <returns>The matching ThreefishModes string name</returns>
	static std::string ToName(ThreefishModes Enumeral);

	/// <summary>
	/// Derive the ThreefishModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The ThreefishModes string name</param>
	///
	/// <returns>The matching ThreefishModes enumeration type name</returns>
	static ThreefishModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
