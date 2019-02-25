#ifndef CEX_STREAMCIPHERS_H
#define CEX_STREAMCIPHERS_H

#include "CexDomain.h"
#include "SymmetricCiphers.h"

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
	/// The Authenticated Stream Cipher; using RHX-HMAC256
	/// </summary>
	ACS256H = static_cast<byte>(SymmetricCiphers::ACS256H),
	/// <summary>
	/// The Authenticated Stream Cipher; using RHX-HMAC512
	/// </summary>
	ACS512H = static_cast<byte>(SymmetricCiphers::ACS512H),
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC256
	/// </summary>
	ACS256S = static_cast<byte>(SymmetricCiphers::ACS256S),
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC512
	/// </summary>
	ACS512S = static_cast<byte>(SymmetricCiphers::ACS512S),
	/// <summary>
	/// The Authenticated Stream Cipher; no authentication specified
	/// </summary>
	ACS = static_cast<byte>(SymmetricCiphers::ACS),
	/// <summary>
	/// The ChaChaPoly20 stream cipher
	/// </summary>
	CSX256 = static_cast<byte>(SymmetricCiphers::CSX256),
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC256
	/// </summary>
	CSX256AE = static_cast<byte>(SymmetricCiphers::CSX256AE),
	/// <summary>
	/// The ChaChaPoly80 stream cipher
	/// </summary>
	CSX512 = static_cast<byte>(SymmetricCiphers::CSX512),
	/// <summary>
	/// The ChaChaPoly80 stream cipher authenticated with KMAC512
	/// </summary>
	CSX512AE = static_cast<byte>(SymmetricCiphers::CSX512AE),
	/// <summary>
	/// The Threefish 256-bit stream cipher
	/// </summary>
	TSX256 = static_cast<byte>(SymmetricCiphers::TSX256),
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC256
	/// </summary>
	TSX256AE = static_cast<byte>(SymmetricCiphers::TSX256AE),
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	TSX512 = static_cast<byte>(SymmetricCiphers::TSX512),
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC512
	/// </summary>
	TSX512AE = static_cast<byte>(SymmetricCiphers::TSX512AE),
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	TSX1024 = static_cast<byte>(SymmetricCiphers::TSX1024),
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC1024
	/// </summary>
	TSX1024AE = static_cast<byte>(SymmetricCiphers::TSX1024AE)
};

class StreamCipherConvert
{
public:

	/// <summary>
	/// Derive the StreamCiphers formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The StreamCiphers enumeration member</param>
	///
	/// <returns>The matching StreamCiphers string name</returns>
	static std::string ToName(StreamCiphers Enumeral);

	/// <summary>
	/// Derive the StreamCiphers enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The StreamCiphers string name</param>
	///
	/// <returns>The matching StreamCiphers enumeration type name</returns>
	static StreamCiphers FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
