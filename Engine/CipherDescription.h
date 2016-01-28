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

using CEX::Enumeration::BlockSizes;
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
///    CipherDescription cdsc = new CipherDescription(
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
/// <seealso cref="CEX::Enumeration::BlockSizes">CEX::Enumeration BlockSizes Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::CipherModes">CEX::Enumeration CipherModes Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::Digests">CEX::Enumeration Digests Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::IVSizes">CEX::Enumeration IVSizes Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::PaddingModes">CEX::Enumeration PaddingModes Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::RoundCounts">CEX::Enumeration RoundCounts Enumeration</seealso>
/// <seealso cref="CEX::Enumeration::SymmetricEngines">CEX::Enumeration SymmetricEngines Enumeration</seealso>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
class CipherDescription
{
private:
	static constexpr unsigned int ENGTPE_SIZE = 1;
	static constexpr unsigned int KEYSZE_SIZE = 2;
	static constexpr unsigned int IVSIZE_SIZE = 1;
	static constexpr unsigned int CPRTPE_SIZE = 1;
	static constexpr unsigned int PADTPE_SIZE = 1;
	static constexpr unsigned int BLKSZE_SIZE = 1;
	static constexpr unsigned int RNDCNT_SIZE = 1;
	static constexpr unsigned int KDFENG_SIZE = 1;
	static constexpr unsigned int MACSZE_SIZE = 1;
	static constexpr unsigned int MACENG_SIZE = 1;
	static constexpr unsigned int HDR_SIZE = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE + MACENG_SIZE;

	static constexpr unsigned int ENGTPE_SEEK = 0;
	static constexpr unsigned int KEYSZE_SEEK = ENGTPE_SIZE;
	static constexpr unsigned int IVSIZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE;
	static constexpr unsigned int CPRTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
	static constexpr unsigned int PADTPE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE;
	static constexpr unsigned int BLKSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE;
	static constexpr unsigned int RNDCNT_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE;
	static constexpr unsigned int KDFENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;
	static constexpr unsigned int MACSZE_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
	static constexpr unsigned int MACENG_SEEK = ENGTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + CPRTPE_SIZE + PADTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE + MACSZE_SIZE;

	unsigned int _engineType;
	unsigned int _keySize;
	unsigned int _ivSize;
	unsigned int _cipherType;
	unsigned int _paddingType;
	unsigned int _blockSize;
	unsigned int _roundCount;
	unsigned int _kdfEngine;
	unsigned int _macSize;
	unsigned int _macEngine;
	bool _isInitialized;

	CipherDescription() {}

public:

	/// <summary>
	/// The Cryptographic <see cref="CEX::Enumeration::SymmetricEngines">Engine</see> type
	/// </summary>
	const SymmetricEngines EngineType() const { return (SymmetricEngines)_engineType; }

	/// <summary>
	/// The cipher Key Size
	/// </summary>
	const unsigned int KeySize() const { return _keySize; }
	unsigned int &KeySize() { return _keySize; }

	/// <summary>
	/// Size of the cipher <see cref="CEX::Enumeration::IVSizes">Initialization Vector</see>
	/// </summary>
	const IVSizes IvSize() const { return (IVSizes)_ivSize; }

	/// <summary>
	/// The type of <see cref="CEX::Enumeration::CipherModes">Cipher Mode</see>
	/// </summary>
	const CipherModes CipherType() const { return (CipherModes)_cipherType; }

	/// <summary>
	/// The type of cipher <see cref="CEX::Enumeration::PaddingModes">Padding Mode</see>
	/// </summary>
	const PaddingModes PaddingType() const { return (PaddingModes)_paddingType; }

	/// <summary>
	/// The cipher <see cref="CEX::Enumeration::BlockSizes">Block Size</see>
	/// </summary>
	const BlockSizes BlockSize() const { return (BlockSizes)_blockSize; }

	/// <summary>
	/// The number of diffusion <see cref="CEX::Enumeration::RoundCounts">Rounds</see>
	/// </summary>
	const RoundCounts RoundCount() const { return (RoundCounts)_roundCount; }

	/// <summary>
	/// The <see cref="CEX::Enumeration::Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
	/// </summary>
	const Digests KdfEngine() const { return (Digests)_kdfEngine; }

	/// <summary>
	/// The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key
	/// </summary>
	const unsigned int MacSize() const { return _macSize; }

	/// <summary>
	/// The HMAC <see cref="CEX::Enumeration::Digests">Digest</see> engine used to authenticate a message file encrypted with this key
	/// </summary>
	const Digests MacEngine() const { return (Digests)_macEngine; }

	/// <summary>
	/// The cipher initialization status
	/// </summary>
	const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// CipherDescription constructor
	/// </summary>
	/// 
	/// <param name="EngineType">The Cryptographic <see cref="CEX::Enumeration::SymmetricEngines">Engine</see> type</param>
	/// <param name="KeySize">The cipher Key Size in bytes</param>
	/// <param name="IvSize">Size of the cipher <see cref="CEX::Enumeration::IVSizes">Initialization Vector</see></param>
	/// <param name="CipherType">The type of <see cref="CEX::Enumeration::CipherModes">Cipher Mode</see></param>
	/// <param name="PaddingType">The type of cipher <see cref="CEX::Enumeration::PaddingModes">Padding Mode</see></param>
	/// <param name="BlockSize">The cipher <see cref="CEX::Enumeration::BlockSizes">Block Size</see></param>
	/// <param name="RoundCount">The number of diffusion <see cref="CEX::Enumeration::RoundCounts">Rounds</see></param>
	/// <param name="KdfEngine">The <see cref="CEX::Enumeration::Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	/// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
	/// <param name="MacEngine">The HMAC <see cref="CEX::Enumeration::Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
	CipherDescription(SymmetricEngines EngineType, unsigned int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType, BlockSizes BlockSize, 
		RoundCounts RoundCount, Digests KdfEngine = Digests::SHA512, unsigned int MacSize = 64, Digests MacEngine = Digests::SHA512)
		:
		_engineType(0), 
		_keySize(0),
		_ivSize(0),
		_cipherType(0),
		_paddingType(0),
		_blockSize(0),
		_roundCount(0),
		_kdfEngine(0),
		_macSize(0),
		_macEngine(0)
	{
		this->_engineType = (unsigned int)EngineType;
		this->_keySize = KeySize;
		this->_ivSize = (unsigned int)IvSize;
		this->_cipherType = (unsigned int)CipherType;
		this->_paddingType = (unsigned int)PaddingType;
		this->_blockSize = (unsigned int)BlockSize;
		this->_roundCount = (unsigned int)RoundCount;
		this->_kdfEngine = (unsigned int)KdfEngine;
		this->_macSize = MacSize;
		this->_macEngine = (unsigned int)MacEngine;

		_isInitialized = true;
	}

	/// <summary>
	/// Initialize the CipherDescription structure using a byte array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
	CipherDescription(std::vector<byte> &DescriptionArray)
	{
		CEX::IO::StreamReader reader(DescriptionArray);

		_engineType = reader.ReadByte();
		_keySize = reader.ReadInt16();
		_ivSize = reader.ReadByte();
		_cipherType = reader.ReadByte();
		_paddingType = reader.ReadByte();
		_blockSize = reader.ReadByte();
		_roundCount = reader.ReadByte();
		_kdfEngine = reader.ReadByte();
		_macSize = reader.ReadByte();
		_macEngine = reader.ReadByte();
	}

	/// <summary>
	/// Initialize the CipherDescription structure using a Stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
	CipherDescription(CEX::IO::MemoryStream &DescriptionStream)
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
		_macSize = reader.ReadByte();
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
		_macSize = 0;
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
		writer.Write((byte)_macSize);
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
		writer.Write((byte)_macSize);
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
		result += 31 * _macSize;
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
		if (_engineType != (unsigned int)Obj.EngineType())
			return false;
		if (_keySize != Obj.KeySize())
			return false;
		if (_ivSize != (unsigned int)Obj.IvSize())
			return false;
		if (_cipherType != (unsigned int)Obj.CipherType())
			return false;
		if (_paddingType != (unsigned int)Obj.PaddingType())
			return false;
		if (_blockSize != (unsigned int)Obj.BlockSize())
			return false;
		if (_roundCount != (unsigned int)Obj.RoundCount())
			return false;
		if (_kdfEngine != (unsigned int)Obj.KdfEngine())
			return false;
		if (_macSize != Obj.MacSize())
			return false;
		if (_macEngine != (unsigned int)Obj.MacEngine())
			return false;

		return true;
	}
};

NAMESPACE_COMMONEND
#endif