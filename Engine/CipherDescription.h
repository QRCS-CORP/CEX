#ifndef _CEXENGINE_CIPHERDESCRIPTION_H
#define _CEXENGINE_CIPHERDESCRIPTION_H

#include "Common.h"
#include "BlockSizes.h"
#include "CipherModes.h"
#include "Digests.h"
#include "IVSizes.h"
#include "MemoryStream.h"
#include "PaddingModes.h"
#include "RoundCounts.h"
#include "SymmetricEngines.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_COMMON

using CEX::Enumeration::BlockSizes; //TODO ?
using CEX::Enumeration::CipherModes;
using CEX::Enumeration::Digests;
using CEX::Enumeration::IVSizes;
using CEX::Enumeration::PaddingModes;
using CEX::Enumeration::RoundCounts;
using CEX::Enumeration::SymmetricEngines;

/// <summary>
/// The CipherDescription structure.
/// <para>Used in conjunction with the CipherStream class.
/// Contains all the necessary settings required to recreate a cipher instance.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of populating a <c>CipherDescription</c> structure:</description>
/// <code>
///    CipherDescription dsc(
///        Engines.RHX,             // cipher engine
///        192,                     // key size in bytes
///        IVSizes.V128,            // cipher iv size enum
///        CipherModes.CTR,         // cipher mode enum
///        PaddingModes.X923,       // cipher padding mode enum
///        BlockSizes.B128,         // block size enum
///        RoundCounts.R18,         // diffusion rounds enum
///        Digests.Skein512,        // cipher kdf engine
///        64,                      // mac size
///        Digests.Keccak);         // mac digest
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::BlockSizes"/>
/// <seealso cref="CEX::Enumeration::CipherModes"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// <seealso cref="CEX::Enumeration::IVSizes"/>
/// <seealso cref="CEX::Enumeration::PaddingModes"/>
/// <seealso cref="CEX::Enumeration::RoundCounts"/>
/// <seealso cref="CEX::Enumeration::SymmetricEngines"/>
class CipherDescription
{
private:
	static constexpr uint ENGTPE_SIZE = 1;
	static constexpr uint KEYSZE_SIZE = 2;
	static constexpr uint IVSIZE_SIZE = 1;
	static constexpr uint CPRTPE_SIZE = 1;
	static constexpr uint PADTPE_SIZE = 1;
	static constexpr uint BLKSZE_SIZE = 1;
	static constexpr uint RNDCNT_SIZE = 1;
	static constexpr uint KDFENG_SIZE = 1;
	static constexpr uint MACSZE_SIZE = 1;
	static constexpr uint MACENG_SIZE = 1;
	static constexpr uint HDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE + MACENG_SIZE;

	static constexpr uint ENGTPE_SEEK = 0;
	static constexpr uint KEYSZE_SEEK = ENGTPE_SIZE;
	static constexpr uint IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
	static constexpr uint CPRTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
	static constexpr uint PADTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE;
	static constexpr uint BLKSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE;
	static constexpr uint RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE;
	static constexpr uint KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
	static constexpr uint MACSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
	static constexpr uint MACENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE;

	uint _engineType;
	uint _keySize;
	uint _ivSize;
	uint _cipherType;
	uint _paddingType;
	uint _blockSize;
	uint _roundCount;
	uint _kdfEngine;
	uint _macKeySize;
	uint _macEngine;

public:

	/// <summary>
	/// The Cryptographic Engine type
	/// </summary>
	const CEX::Enumeration::SymmetricEngines EngineType() const { return (CEX::Enumeration::SymmetricEngines)_engineType; }

	/// <summary>
	/// Get: The cipher Key Size
	/// </summary>
	const uint KeySize() const { return _keySize; }

	/// <summary>
	/// Set: The cipher Key Size
	/// </summary>
	uint &KeySize() { return _keySize; }

	/// <summary>
	/// Size of the cipher Initialization Vector
	/// </summary>
	const CEX::Enumeration::IVSizes IvSize() const { return (CEX::Enumeration::IVSizes)_ivSize; }

	/// <summary>
	/// The type of Cipher Mode
	/// </summary>
	const CEX::Enumeration::CipherModes CipherType() const { return (CEX::Enumeration::CipherModes)_cipherType; }

	/// <summary>
	/// The type of cipher Padding Mode
	/// </summary>
	const CEX::Enumeration::PaddingModes PaddingType() const { return (CEX::Enumeration::PaddingModes)_paddingType; }

	/// <summary>
	/// The cipher Block Size
	/// </summary>
	const CEX::Enumeration::BlockSizes BlockSize() const { return (CEX::Enumeration::BlockSizes)_blockSize; }

	/// <summary>
	/// The number of diffusion Rounds
	/// </summary>
	const CEX::Enumeration::RoundCounts RoundCount() const { return (CEX::Enumeration::RoundCounts)_roundCount; }

	/// <summary>
	/// The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers
	/// </summary>
	const CEX::Enumeration::Digests KdfEngine() const { return (CEX::Enumeration::Digests)_kdfEngine; }

	/// <summary>
	/// The size of the HMAC key in bytes; a zeroed parameter means authentication is not enabled with this key
	/// </summary>
	const uint MacKeySize() const { return _macKeySize; }

	/// <summary>
	/// The HMAC Digest engine used to authenticate a message file encrypted with this key
	/// </summary>
	const CEX::Enumeration::Digests MacEngine() const { return (CEX::Enumeration::Digests)_macEngine; }

	/// <summary>
	/// Default constructor
	/// </summary>
	CipherDescription() 
		:
		_engineType(0),
		_keySize(0),
		_ivSize(0),
		_cipherType(0),
		_paddingType(0),
		_blockSize(0),
		_roundCount(0),
		_kdfEngine(0),
		_macKeySize(0),
		_macEngine(0)
	{}

	/// <summary>
	/// CipherDescription constructor
	/// </summary>
	/// 
	/// <param name="EngineType">The Cryptographic Engine type</param>
	/// <param name="KeySize">The cipher Key Size in bytes</param>
	/// <param name="IvSize">Size of the cipher Initialization Vector</param>
	/// <param name="CipherType">The type of Cipher Mode</param>
	/// <param name="PaddingType">The type of cipher Padding Mode</param>
	/// <param name="BlockSize">The cipher Block Size</param>
	/// <param name="RoundCount">The number of diffusion Rounds</param>
	/// <param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	/// <param name="MacKeySize">The size of the HMAC key in bytes; a zeroed parameter means authentication is not enabled with this key</param>
	/// <param name="MacEngine">The HMAC Digest engine used to authenticate a message file encrypted with this key</param>
	CipherDescription(CEX::Enumeration::SymmetricEngines EngineType, uint KeySize, CEX::Enumeration::IVSizes IvSize, CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::PaddingModes PaddingType, CEX::Enumeration::BlockSizes BlockSize,
		CEX::Enumeration::RoundCounts RoundCount, CEX::Enumeration::Digests KdfEngine = CEX::Enumeration::Digests::SHA512, uint MacKeySize = 64, CEX::Enumeration::Digests MacEngine = CEX::Enumeration::Digests::SHA512)
	{
		this->_engineType = (uint)EngineType;
		this->_keySize = KeySize;
		this->_ivSize = (uint)IvSize;
		this->_cipherType = (uint)CipherType;
		this->_paddingType = (uint)PaddingType;
		this->_blockSize = (uint)BlockSize;
		this->_roundCount = (uint)RoundCount;
		this->_kdfEngine = (uint)KdfEngine;
		this->_macKeySize = MacKeySize;
		this->_macEngine = (uint)MacEngine;
	}

	/// <summary>
	/// Initialize the CipherDescription structure using a byte array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
	explicit CipherDescription(const std::vector<byte> &DescriptionArray)
	{
		CEX::IO::MemoryStream ms = CEX::IO::MemoryStream(DescriptionArray);
		CEX::IO::StreamReader reader(ms);

		_engineType = reader.ReadByte();
		_keySize = reader.ReadInt16();
		_ivSize = reader.ReadByte();
		_cipherType = reader.ReadByte();
		_paddingType = reader.ReadByte();
		_blockSize = reader.ReadByte();
		_roundCount = reader.ReadByte();
		_kdfEngine = reader.ReadByte();
		_macKeySize = reader.ReadByte();
		_macEngine = reader.ReadByte();
	}

	/// <summary>
	/// Initialize the CipherDescription structure using a Stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
	explicit CipherDescription(const CEX::IO::MemoryStream &DescriptionStream)
	{
		CEX::IO::StreamReader reader(DescriptionStream);

		_engineType = reader.ReadByte();
		_keySize = reader.ReadInt16();
		_ivSize = reader.ReadByte();
		_cipherType = reader.ReadByte();
		_paddingType = reader.ReadByte();
		_blockSize = reader.ReadByte();
		_roundCount = reader.ReadByte();
		_kdfEngine = reader.ReadByte();
		_macKeySize = reader.ReadByte();
		_macEngine = reader.ReadByte();
	}

	/// <summary>
	/// Get the header Size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return HDR_SIZE;
	}

	/// <summary>
	/// Reset all struct members
	/// </summary>
	void Reset()
	{
		_engineType = 0;
		_keySize = 0;
		_ivSize = 0;
		_cipherType = 0;
		_paddingType = 0;
		_blockSize = 0;
		_roundCount = 0;
		_kdfEngine = 0;
		_macKeySize = 0;
		_macEngine = 0;
	}

	/// <summary>
	/// Convert the CipherDescription structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the CipherDescription</returns>
	std::vector<byte> ToBytes()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write((byte)_engineType);
		writer.Write((short)_keySize);
		writer.Write((byte)_ivSize);
		writer.Write((byte)_cipherType);
		writer.Write((byte)_paddingType);
		writer.Write((byte)_blockSize);
		writer.Write((byte)_roundCount);
		writer.Write((byte)_kdfEngine);
		writer.Write((byte)_macKeySize);
		writer.Write((byte)_macEngine);

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the CipherDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the CipherDescription</returns>
	CEX::IO::MemoryStream* ToStream()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write((byte)_engineType);
		writer.Write((short)_keySize);
		writer.Write((byte)_ivSize);
		writer.Write((byte)_cipherType);
		writer.Write((byte)_paddingType);
		writer.Write((byte)_blockSize);
		writer.Write((byte)_roundCount);
		writer.Write((byte)_kdfEngine);
		writer.Write((byte)_macKeySize);
		writer.Write((byte)_macEngine);

		return writer.GetStream();
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = 1;

		result += 31 * _engineType;
		result += 31 * _keySize;
		result += 31 * _ivSize;
		result += 31 * _cipherType;
		result += 31 * _paddingType;
		result += 31 * _blockSize;
		result += 31 * _roundCount;
		result += 31 * _kdfEngine;
		result += 31 * _macKeySize;
		result += 31 * _macEngine;

		return result;
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(CipherDescription &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}
};

NAMESPACE_COMMONEND
#endif