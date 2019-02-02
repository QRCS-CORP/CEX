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
	/// The Authenticated Stream Cipher; using RHX-KMAC256
	/// </summary>
	ACS256A = static_cast<byte>(SymmetricCiphers::ACS256A),
	/// <summary>
	/// The Authenticated Stream Cipher; using RHX-KMAC512
	/// </summary>
	ACS512A = static_cast<byte>(SymmetricCiphers::ACS512A),
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC256
	/// </summary>
	ACS256S = static_cast<byte>(SymmetricCiphers::ACS256S),
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC512
	/// </summary>
	ACS512S = static_cast<byte>(SymmetricCiphers::ACS512S),
	/// <summary>
	/// The Authenticated Stream Cipher; using default parameters RHX-CSHAKE512-KMAC512
	/// </summary>
	ACS = static_cast<byte>(SymmetricCiphers::ACS),
	/// <summary>
	/// The ChaChaPoly20 stream cipher
	/// </summary>
	ChaCha256 = static_cast<byte>(SymmetricCiphers::ChaCha256),
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC256
	/// </summary>
	ChaCha256AE = static_cast<byte>(SymmetricCiphers::ChaCha256AE),
	/// <summary>
	/// The ChaChaPoly80 stream cipher
	/// </summary>
	ChaCha512 = static_cast<byte>(SymmetricCiphers::ChaCha512),
	/// <summary>
	/// The ChaChaPoly80 stream cipher authenticated with KMAC512
	/// </summary>
	ChaCha512AE = static_cast<byte>(SymmetricCiphers::ChaCha512AE),
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
