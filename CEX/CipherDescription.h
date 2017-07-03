#ifndef _CEX_CIPHERDESCRIPTION_H
#define _CEX_CIPHERDESCRIPTION_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockSizes.h"
#include "CipherModes.h"
#include "Digests.h"
#include "IVSizes.h"
#include "MemoryStream.h"
#include "PaddingModes.h"
#include "RoundCounts.h"

NAMESPACE_PROCESSING

using Enumeration::BlockCiphers;
using Enumeration::BlockSizes;
using Enumeration::CipherModes;
using Enumeration::Digests;
using Enumeration::IVSizes;
using Enumeration::PaddingModes;
using Enumeration::RoundCounts;
using IO::MemoryStream;

/// <summary>
/// The CipherDescription structure.
/// <para>Used in conjunction with the CipherStream class.
/// Contains all the necessary settings required to recreate a cipher instance.</para>
/// </summary>
/// 
/// <example>
/// <description>Populating a CipherDescription structure:</description>
/// <code>
///    CipherDescription dsc(
///        Engines.RHX,             // cipher engine
///        192,                     // key size in bytes
///        IVSizes.V128,            // cipher iv size
///        CipherModes.CTR,         // cipher mode
///        PaddingModes.X923,       // cipher padding mode
///        BlockSizes.B128,         // block size
///        RoundCounts.R18,         // transformation rounds
///        Digests.Skein512);       // kdf digest
/// </code>
/// </example>
class CipherDescription
{
private:

	static const uint HDR_SIZE = 9;

	byte m_engineType;
	short m_keySize;
	byte m_ivSize;
	byte m_cipherType;
	byte m_paddingType;
	byte m_blockSize;
	byte m_roundCount;
	byte m_kdfEngine;

public:

	CipherDescription& operator=(const CipherDescription&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// The Cryptographic Engine type
	/// </summary>
	const BlockCiphers EngineType();

	/// <summary>
	/// Get: The cipher Key Size
	/// </summary>
	const short KeySize() const;

	/// <summary>
	/// Set: The cipher Key Size
	/// </summary>
	short &KeySize();

	/// <summary>
	/// Size of the cipher Initialization Vector
	/// </summary>
	const IVSizes IvSize();

	/// <summary>
	/// The type of Cipher Mode
	/// </summary>
	const CipherModes CipherType();

	/// <summary>
	/// The type of cipher Padding Mode
	/// </summary>
	const PaddingModes PaddingType();

	/// <summary>
	/// The cipher Block Size
	/// </summary>
	const BlockSizes BlockSize();

	/// <summary>
	/// The number of transformation Rounds
	/// </summary>
	const RoundCounts RoundCount();

	/// <summary>
	/// The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers
	/// </summary>
	const Digests KdfEngine();

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor
	/// </summary>
	CipherDescription();

	/// <summary>
	/// Initialize a CipherDescription struct
	/// </summary>
	/// 
	/// <param name="EngineType">The cipher type</param>
	/// <param name="KeySize">The cipher key size in bytes</param>
	/// <param name="IvSize">Size of the cipher Initialization Vector</param>
	/// <param name="CipherType">The type of cipher mode</param>
	/// <param name="PaddingType">The type of cipher padding mode</param>
	/// <param name="BlockSize">The cipher block size</param>
	/// <param name="RoundCount">The number of transformation rounds</param>
	/// <param name="KdfEngine">The digest engine used to power the key schedule key derivation Function in HX extended ciphers</param>
	CipherDescription(BlockCiphers EngineType, short KeySize, IVSizes IvSize, CipherModes CipherType,
		PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine = Digests::SHA512);

	/// <summary>
	/// Initialize the CipherDescription structure using a byte array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
	explicit CipherDescription(const std::vector<byte> &DescriptionArray);

	/// <summary>
	/// Initialize the CipherDescription structure using a Stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
	explicit CipherDescription(const MemoryStream &DescriptionStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~CipherDescription();

	//~~~Public Functions~~~//

	/// <summary>
	/// An AES-128 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription AES128CBC();

	/// <summary>
	/// An AES-256 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription AES256CBC();

	/// <summary>
	/// An Rijndael-512 HX extended preset using CBC mode, PKCS7 padding, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription RHX512CBC();

	/// <summary>
	/// An AES-128 preset using CTR mode
	/// </summary>
	static CipherDescription AES128CTR();

	/// <summary>
	/// An AES-256 preset using CTR mode
	/// </summary>
	static CipherDescription AES256CTR();

	/// <summary>
	/// An Rijndael-512 HX extended preset using CTR mode, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription RHX512CTR();

	/// <summary>
	/// An Serpent-256 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription SERPENT256CBC();

	/// <summary>
	/// An Serpent-512 HX extended preset using CBC mode, PKCS7 padding, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription SHX512CBC();

	/// <summary>
	/// An Serpent-256 preset using CTR mode
	/// </summary>
	static CipherDescription SERPENT256CTR();

	/// <summary>
	/// An Serpent-512 HX extended preset using CTR mode, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription SHX512CTR();

	/// <summary>
	/// An Twofish-256 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription TWOFISH256CBC();

	/// <summary>
	/// An Twofish-512 HX extended preset using CBC mode, PKCS7 padding, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription THX512CBC();

	/// <summary>
	/// An Twofish-256 preset using CTR mode
	/// </summary>
	static CipherDescription TWOFISH256CTR();

	/// <summary>
	/// An Twofish-512 HX extended preset using CTR mode, and an SHA256 powered KDF
	/// </summary>
	static CipherDescription THX512CTR();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(CipherDescription &Obj);

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
	/// Convert the CipherDescription structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the CipherDescription</returns>
	std::vector<byte> ToBytes();

	/// <summary>
	/// Convert the CipherDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the CipherDescription</returns>
	MemoryStream* ToStream();
};

NAMESPACE_PROCESSINGEND
#endif