#ifndef CEX_STREAMCIPHERS_H
#define CEX_STREAMCIPHERS_H

#include "CexDomain.h"
#include "StreamAuthenticators.h"
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

	//~~~ ChaCha Stream-cipher Extended Variants~~//

	/// <summary>
	/// A standard implementation of the ChaChaPoly20 stream-cipher, this variant uses 20 rounds and has no athentication.
	/// <para>A standard ChaChaPoly20 stream-cipher implementation: uses a 512-bit block and a 256-bit key, and 8-byte nonce</para>
	/// </summary>
	CSX256 = static_cast<byte>(SymmetricCiphers::CSX256),
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC-256
	/// <para>An extended ChaChaPoly20 stream-cipher implementation: uses a 512-bit block, a 256-bit key size, and 20 rounds</para>
	/// </summary>
	CSXR20K256 = static_cast<byte>(SymmetricCiphers::CSXR20K256),
	/// <summary>
	/// A extended implementation of the ChaCha stream-cipher, this variant uses 80 rounds and has no athentication.
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSX512 = static_cast<byte>(SymmetricCiphers::CSX512),
	/// <summary>
	/// The extended ChaChaP80 stream cipher authenticated with KMAC-512
	/// <para>An extended ChaCha stream-cipher implementation: uses a 512-bit input-block, a 512-bit key, and 80 rounds</para>
	/// </summary>
	CSXR80K512 = static_cast<byte>(SymmetricCiphers::CSXR80K512),

	//~~~ Rijndael-256 Extended Cipher Stream Variants~~//

	/// <summary>
	/// The Rijndael-256 wide-block based authenticated stream cipher, this variant has no athentication.
	/// <para>A Rijndael Extended cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes</para>
	/// </summary>
	RCS = static_cast<byte>(SymmetricCiphers::RCS),
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-256 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK256 = static_cast<byte>(SymmetricCiphers::RCSK256),
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-512 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK512 = static_cast<byte>(SymmetricCiphers::RCSK512),
	/// <summary>
	/// The authenticated Rijndael-256 Stream Cipher; using KMAC-1024 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RCSK1024 = static_cast<byte>(SymmetricCiphers::RCSK1024),

	//~~~ Rijndael-512 Extended Cipher Stream Variants~~//

	/// <summary>
	/// The Rijndael-512 wide-block based authenticated stream cipher, this variant has no athentication.
	/// <para>A Rijndael Extended cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes</para>
	/// </summary>
	RWS = static_cast<byte>(SymmetricCiphers::RWS),
	/// <summary>
	/// The authenticated Rijndael-512 Stream Cipher; using KMAC-256 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RWSK256 = static_cast<byte>(SymmetricCiphers::RWSK256),
	/// <summary>
	/// The authenticated Rijndael-512 Stream Cipher; using KMAC-512 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RWSK512 = static_cast<byte>(SymmetricCiphers::RWSK512),
	/// <summary>
	/// The authenticated Rijndael-512 Stream Cipher; using KMAC1024 for authentication.
	/// <para>Extended Rijndael cipher implementation: uses a 256-bit nonce and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RWSK1024 = static_cast<byte>(SymmetricCiphers::RWSK1024),

	//~~~ Threefish Stream-cipher Extended Variants~~//

	/// <summary>
	/// A standard implementation of the Threefish-256 stream-cipher, this variant uses 72 rounds and has no athentication.
	/// <para>A Threefish-256 stream-cipher: uses a 256-bit block a 256-bit key size</para>
	/// </summary>
	TSX256 = static_cast<byte>(SymmetricCiphers::TSX256),
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC-256.
	/// <para>An extended Threefish-256 stream-cipher implementation: uses a 256-bit block, 72 rounds, and a 256-bit key size</para>
	/// </summary>
	TSXR72K256 = static_cast<byte>(SymmetricCiphers::TSXR72K256),
	/// <summary>
	/// The Threefish 512-bit stream cipher, this variant uses 96 rounds and has no athentication.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSX512 = static_cast<byte>(SymmetricCiphers::TSX512),
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC-512.
	/// <para>An extended Threefish-512 stream-cipher implementation: uses a 512-bit block, 96 rounds, and a 512-bit key size</para>
	/// </summary>
	TSXR96K512 = static_cast<byte>(SymmetricCiphers::TSXR96K512),
	/// <summary>
	/// The Threefish 1024-bit stream cipher, this variant uses 120 rounds and has no athentication.
	/// <para>Extended cipher implementation: uses a 1024-bit block and a 1024-bit key size</para>
	/// </summary>
	TSX1024 = static_cast<byte>(SymmetricCiphers::TSX1024),
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC-1024.
	/// <para>An extended Threefish-1024 stream-cipher implementation: uses a 1024-bit block, 120 rounds, and a 1024-bit key size</para>
	/// </summary>
	TSXR120K1024 = static_cast<byte>(SymmetricCiphers::TSXR120K1024)
};

class StreamCipherConvert
{
public:


	/// <summary>
	/// Derive the StreamCiphers variant enumeration type-name from the base cipher and authentication MAC types
	/// </summary>
	/// 
	/// <param name="Name">The stream-cipher variants enumeration name</param>
	///
	/// <returns>The matching StreamCiphers enumeration type name</returns>
	static StreamCiphers FromDescription(StreamCiphers Enumeral, StreamAuthenticators Authenticator);

	/// <summary>
	/// Derive the StreamCiphers enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The StreamCiphers string name</param>
	///
	/// <returns>The matching StreamCiphers enumeration type name</returns>
	static StreamCiphers FromName(std::string &Name);

	/// <summary>
	/// Derive the StreamCiphers formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The StreamCiphers enumeration member</param>
	///
	/// <returns>The matching StreamCiphers string name</returns>
	static std::string ToName(StreamCiphers Enumeral);


};

NAMESPACE_ENUMERATIONEND
#endif
