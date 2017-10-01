#ifndef CEX_MACDESCRIPTION_H
#define CEX_MACDESCRIPTION_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockSizes.h"
#include "CipherModes.h"
#include "Digests.h"
#include "IVSizes.h"
#include "KeySizes.h"
#include "Macs.h"
#include "MemoryStream.h"
#include "PaddingModes.h"
#include "RoundCounts.h"

NAMESPACE_PROCESSING

using Enumeration::BlockCiphers;
using Enumeration::BlockSizes;
using Enumeration::CipherModes;
using Enumeration::Digests;
using Enumeration::IVSizes;
using Enumeration::KeySizes;
using Enumeration::Macs;
using Enumeration::PaddingModes;
using Enumeration::RoundCounts;
using IO::MemoryStream;

/// <summary>
/// The MacDescription structure.
/// <para>Used in conjunction with the MacStream class.
/// Contains all the necessary settings required to recreate a Mac instance.</para>
/// </summary>
/// 
/// <example>
/// <description>Populating a MacDescription for an Hmac:</description>
/// <code>
///    MacDescription md(
///        Digests.SHA512,	// hmac engine
///        128);			// key size in bytes
/// </code>
/// </example>
class MacDescription
{
private:

	static const uint MACHDR_SIZE = 9;

	byte m_macType;
	short m_keySize;
	byte m_ivSize;
	byte m_hmacEngine;
	byte m_engineType;
	byte m_blockSize;
	byte m_roundCount;
	byte m_kdfEngine;

public:

	MacDescription& operator=(const MacDescription&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// The cipher internal Block Size
	/// </summary>
	const BlockSizes BlockSize();

	/// <summary>
	/// The symmetric block cipher Engine type
	/// </summary>
	const BlockCiphers EngineType();

	/// <summary>
	/// The HMAC Digest engine used to authenticate a message file encrypted with this key
	/// </summary>
	const Digests HmacEngine();

	/// <summary>
	/// Size of the cipher Initialization Vector
	/// </summary>
	const IVSizes IvSize();

	/// <summary>
	/// The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers
	/// </summary>
	const Digests KdfEngine();

	/// <summary>
	/// The cipher Key Size
	/// </summary>
	const short KeySize();

	/// <summary>
	/// The type of Mac engine to use; CMac, Hmac, or Vmac.
	/// </summary>
	const Macs MacType();

	/// <summary>
	/// The number of cipher transformation Rounds
	/// </summary>
	const RoundCounts RoundCount();

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor
	/// </summary>
	explicit MacDescription();

	/// <summary>
	/// Initialize the structure with parameters for any supported type of Mac generator
	/// </summary>
	/// 
	/// <param name="MacType">The type of Mac generator; Cmac, Hmac, or Vmac</param>
	/// <param name="KeySize">The mac/cipher key size in bytes</param>
	/// <param name="IvSize">Size of the Mac Initialization Vector</param>
	/// <param name="HmacEngine">The Digest engine used in the Hmac</param>
	/// <param name="EngineType">The symmetric block cipher Engine type</param>
	/// <param name="BlockSize">The cipher Block Size</param>
	/// <param name="RoundCount">The number of transformation Rounds</param>
	/// <param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	explicit MacDescription(Macs MacType, short KeySize, byte IvSize, Digests HmacEngine = Digests::SHA512, BlockCiphers EngineType = BlockCiphers::RHX,
		BlockSizes BlockSize = BlockSizes::B128, RoundCounts RoundCount = RoundCounts::R14, Digests KdfEngine = Digests::SHA512);

	/// <summary>
	/// Initialize the structure with parameters for an HMAC generator
	/// </summary>
	/// 
	/// <param name="KeySize">The Mac key size in bytes</param>
	/// <param name="HmacEngine">The Digest engine used in the Hmac</param>
	explicit MacDescription(uint KeySize, Digests HmacEngine);

	/// <summary>
	/// Initialize the structure with parameters for an CMAC generator
	/// </summary>
	/// 
	/// <param name="KeySize">The Mac key size in bytes</param>
	/// <param name="EngineType">The symmetric block cipher Engine type</param>
	/// <param name="IvSize">Size of the cipher Initialization Vector</param>
	/// <param name="BlockSize">The cipher Block Size</param>
	/// <param name="RoundCount">The number of transformation Rounds</param>
	/// <param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	explicit MacDescription(short KeySize, BlockCiphers EngineType, IVSizes IvSize, BlockSizes BlockSize = BlockSizes::B128,
		RoundCounts RoundCount = RoundCounts::R14, Digests KdfEngine = Digests::SHA512);

	/// <summary>
	/// Initialize the MacDescription structure using a Stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the MacDescription</param>
	explicit MacDescription(const MemoryStream &DescriptionStream);

	/// <summary>
	/// Initialize the MacDescription structure using a byte array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the MacDescription</param>
	explicit MacDescription(const std::vector<byte> &DescriptionArray);

	//~~~Presets~~~//

	/// <summary>
	/// An HMAC SHA-256 preset
	/// </summary>
	static MacDescription HMACSHA256();

	/// <summary>
	/// An HMAC SHA-512 preset
	/// </summary>
	static MacDescription HMACSHA512();

	/// <summary>
	/// An CMAC AES-256 preset
	/// </summary>
	static MacDescription CMACAES256();

	//~~~Public Functions~~~//

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(MacDescription &Input);

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode();

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize();

	/// <summary>
	/// Reset all struct members
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the MacDescription structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MacDescription</returns>
	std::vector<byte> ToBytes();

	/// <summary>
	/// Convert the MacDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MacDescription</returns>
	MemoryStream* ToStream();
};

NAMESPACE_PROCESSINGEND
#endif
