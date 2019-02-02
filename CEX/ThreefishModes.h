#ifndef CEX_THREEFISHMODES_H
#define CEX_THREEFISHMODES_H

#include "CexDomain.h"
#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Threefish stream cipher operation-modes enumeration names
/// </summary>
enum class ThreefishModes : byte
{
	/// <summary>
	/// No Threefish mode has been selected
	/// </summary>
	None = 0,
	/// <summary>
	/// The Threefish 256-bit stream cipher
	/// </summary>
	Threefish256 = static_cast<byte>(SymmetricCiphers::Threefish256),
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC256
	/// </summary>
	Threefish256AE = static_cast<byte>(SymmetricCiphers::Threefish256AE),
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	Threefish512 = static_cast<byte>(SymmetricCiphers::Threefish512),
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC512
	/// </summary>
	Threefish512AE = static_cast<byte>(SymmetricCiphers::Threefish512AE),
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	Threefish1024 = static_cast<byte>(SymmetricCiphers::Threefish1024),
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC1024
	/// </summary>
	Threefish1024AE = static_cast<byte>(SymmetricCiphers::Threefish1024AE)
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
