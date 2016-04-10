#ifndef _CEXENGINE_MACDESCRIPTION_H
#define _CEXENGINE_MACDESCRIPTION_H

#include "Common.h"
#include "BlockCiphers.h"
#include "BlockSizes.h"
#include "CipherModes.h"
#include "Digests.h"
#include "IVSizes.h"
#include "Macs.h"
#include "MemoryStream.h"
#include "PaddingModes.h"
#include "RoundCounts.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_COMMON

using CEX::Enumeration::BlockSizes; //TODO ?
using CEX::Enumeration::CipherModes;
using CEX::Enumeration::Digests;
using CEX::Enumeration::IVSizes;
using CEX::Enumeration::Macs;
using CEX::Enumeration::PaddingModes;
using CEX::Enumeration::RoundCounts;
using CEX::Enumeration::BlockCiphers;

/// <summary>
/// The MacDescription structure.
/// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.MacStream"/> class.
/// Contains all the necessary settings required to recreate a Mac instance.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of populating a <c>MacDescription</c> for an Hmac:</description>
/// <code>
///    MacDescription msc(
///        Digests.SHA512,          // hmac engine
///        128);                    // key size in bytes
/// </code>
/// </example>
/// 
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.VolumeCipher"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator"/>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams"/>
class MacDescription
{
private:
	static constexpr uint MACTPE_SIZE = 1;
	static constexpr uint KEYSZE_SIZE = 2;
	static constexpr uint IVSIZE_SIZE = 1;
	static constexpr uint MACENG_SIZE = 1;
	static constexpr uint MACKEY_SIZE = 1;
	static constexpr uint ENGTPE_SIZE = 1;
	static constexpr uint BLKSZE_SIZE = 1;
	static constexpr uint RNDCNT_SIZE = 1;
	static constexpr uint KDFENG_SIZE = 1;
	static constexpr uint MACHDR_SIZE = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + MACKEY_SIZE + ENGTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE + KDFENG_SIZE;
	static constexpr uint MACTPE_SEEK = 0;
	static constexpr uint KEYSZE_SEEK = MACTPE_SIZE;
	static constexpr uint IVSIZE_SEEK = MACTPE_SIZE + KEYSZE_SIZE;
	static constexpr uint MACENG_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE;
	static constexpr uint MACKEY_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE;
	static constexpr uint ENGTPE_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + MACKEY_SIZE;
	static constexpr uint BLKSZE_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + MACKEY_SIZE + ENGTPE_SIZE;
	static constexpr uint RNDCNT_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + MACKEY_SIZE + ENGTPE_SIZE + BLKSZE_SIZE;
	static constexpr uint KDFENG_SEEK = MACTPE_SIZE + KEYSZE_SIZE + IVSIZE_SIZE + MACENG_SIZE + MACKEY_SIZE + ENGTPE_SIZE + BLKSZE_SIZE + RNDCNT_SIZE;

	uint _macType;
	uint _keySize;
	uint _ivSize;
	uint _hmacEngine;
	uint _engineType;
	uint _blockSize;
	uint _roundCount;
	uint _kdfEngine;

public:
	/// <summary>
	/// The type of Mac engine to use; CMac, Hmac, or Vmac.
	/// </summary>
	const CEX::Enumeration::Macs MacType() const { return (CEX::Enumeration::Macs)_macType; }
	/// <summary>
	/// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeySizes">Key Size</see>
	/// </summary>
	const uint KeySize() const { return _keySize; }
	/// <summary>
	/// Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see>
	/// </summary>
	const CEX::Enumeration::IVSizes IvSize() const { return (CEX::Enumeration::IVSizes)_ivSize; }
	/// <summary>
	/// The HMAC <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to authenticate a message file encrypted with this key
	/// </summary>
	const CEX::Enumeration::Digests HmacEngine() const { return (CEX::Enumeration::Digests)_hmacEngine; }
	/// <summary>
	/// The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockCiphers">Engine</see> type
	/// </summary>
	const CEX::Enumeration::BlockCiphers EngineType() const { return (CEX::Enumeration::BlockCiphers)_engineType; }
	/// <summary>
	/// The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see>
	/// </summary>
	const CEX::Enumeration::BlockSizes BlockSize() const { return (CEX::Enumeration::BlockSizes)_blockSize; }
	/// <summary>
	/// The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see>
	/// </summary>
	const CEX::Enumeration::RoundCounts RoundCount() const { return (CEX::Enumeration::RoundCounts)_roundCount; }
	/// <summary>
	/// The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers
	/// </summary>
	const CEX::Enumeration::Digests KdfEngine() const { return (CEX::Enumeration::Digests)_kdfEngine; }

	/// <summary>
	/// Default constructor
	/// </summary>
	MacDescription()
		:
		_macType(0),
		_keySize(0),
		_ivSize(0),
		_hmacEngine(0),
		_engineType(0),
		_blockSize(0),
		_roundCount(0),
		_kdfEngine(0)
	{}

	/// <summary>
	/// Initialize the structure with parameters for any supported type of Mac generator
	/// </summary>
	/// 
	/// <param name="MacType">The type of Mac generator; Cmac, Hmac, or Vmac</param>
	/// <param name="KeySize">The mac/cipher key size in bytes</param>
	/// <param name="IvSize">Size of the Mac Initialization Vector</param>
	/// <param name="HmacEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used in the Hmac</param>
	/// <param name="EngineType">The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
	/// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
	/// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
	/// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	MacDescription(CEX::Enumeration::Macs MacType, uint KeySize, uint IvSize, CEX::Enumeration::Digests HmacEngine = CEX::Enumeration::Digests::SHA512, CEX::Enumeration::BlockCiphers EngineType = CEX::Enumeration::BlockCiphers::RHX,
		CEX::Enumeration::BlockSizes BlockSize = CEX::Enumeration::BlockSizes::B128, CEX::Enumeration::RoundCounts RoundCount = CEX::Enumeration::RoundCounts::R14, CEX::Enumeration::Digests KdfEngine = CEX::Enumeration::Digests::SHA512)
	{
		_macType = (uint)MacType;
		_keySize = KeySize;
		_ivSize = IvSize;
		_hmacEngine = (uint)HmacEngine;
		_engineType = (uint)EngineType;
		_blockSize = (uint)BlockSize;
		_roundCount = (uint)RoundCount;
		_kdfEngine = (uint)KdfEngine;
	}

	/// <summary>
	/// Initialize the structure with parameters for an HMAC generator
	/// </summary>
	/// 
	/// <param name="KeySize">The Mac key size in bytes</param>
	/// <param name="HmacEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used in the Hmac</param>
	MacDescription(uint KeySize, CEX::Enumeration::Digests HmacEngine)
	{
		_macType = (uint)CEX::Enumeration::Macs::HMAC;
		_keySize = KeySize;
		_hmacEngine = (uint)HmacEngine;
		_ivSize = 0;
		_engineType = 0;
		_blockSize = 0;
		_roundCount = 0;
		_kdfEngine = 0;
	}

	/// <summary>
	/// Initialize the structure with parameters for an CMAC generator
	/// </summary>
	/// 
	/// <param name="KeySize">The Mac key size in bytes</param>
	/// <param name="EngineType">The symmetric block cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
	/// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
	/// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
	/// <param name="RoundCount">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
	/// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	MacDescription(uint KeySize, CEX::Enumeration::BlockCiphers EngineType, CEX::Enumeration::IVSizes IvSize, CEX::Enumeration::BlockSizes BlockSize = CEX::Enumeration::BlockSizes::B128,
		CEX::Enumeration::RoundCounts RoundCount = CEX::Enumeration::RoundCounts::R14, CEX::Enumeration::Digests KdfEngine = CEX::Enumeration::Digests::SHA512)
	{
		_macType = (uint)CEX::Enumeration::Macs::CMAC;
		_keySize = KeySize;
		_ivSize = (uint)IvSize;
		_hmacEngine = 0;
		_engineType = (uint)EngineType;
		_blockSize = (uint)BlockSize;
		_roundCount = (uint)RoundCount;
		_kdfEngine = (uint)KdfEngine;
	}

	/// <summary>
	/// Initialize the structure with parameters for an VMAC generator
	/// </summary>
	/// 
	/// <param name="KeySize">The Mac key size in bytes</param>
	/// <param name="VectorSize">Size of the VMAC initialization vector in bytes</param>
	MacDescription(uint KeySize, uint VectorSize)
	{
		_macType = (uint)CEX::Enumeration::Macs::VMAC;
		_keySize = KeySize;
		_ivSize = VectorSize;
		_hmacEngine = 0;
		_engineType = 0;
		_blockSize = 0;
		_roundCount = 0;
		_kdfEngine = 0;
	}

	/// <summary>
	/// Initialize the MacDescription structure using a Stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the MacDescription</param>
	MacDescription(const CEX::IO::MemoryStream &DescriptionStream)
	{
		CEX::IO::StreamReader reader(DescriptionStream);

		_macType = reader.ReadByte();
		_keySize = reader.ReadInt16();
		_ivSize = reader.ReadByte();
		_hmacEngine = reader.ReadByte();
		_engineType = reader.ReadByte();
		_blockSize = reader.ReadByte();
		_roundCount = reader.ReadByte();
		_kdfEngine = reader.ReadByte();
	}

	/// <summary>
	/// Initialize the MacDescription structure using a byte array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the MacDescription</param>
	MacDescription(const std::vector<byte> &DescriptionArray)
	{
		CEX::IO::MemoryStream ms = CEX::IO::MemoryStream(DescriptionArray);
		CEX::IO::StreamReader reader(ms);

		_macType = reader.ReadByte();
		_keySize = reader.ReadInt16();
		_ivSize = reader.ReadByte();
		_hmacEngine = reader.ReadByte();
		_engineType = reader.ReadByte();
		_blockSize = reader.ReadByte();
		_roundCount = reader.ReadByte();
		_kdfEngine = reader.ReadByte();
	}

	/// <summary>
	/// Get the header Size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return MACHDR_SIZE;
	}

	/// <summary>
	/// Reset all struct members
	/// </summary>
	void Reset()
	{
		_macType = 0;
		_keySize = 0;
		_ivSize = 0;
		_hmacEngine = 0;
		_engineType = 0;
		_blockSize = 0;
		_roundCount = 0;
		_kdfEngine = 0;
	}

	/// <summary>
	/// Convert the MacDescription structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MacDescription</returns>
	std::vector<byte> ToBytes()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write((byte)_macType);
		writer.Write((short)_keySize);
		writer.Write((byte)_ivSize);
		writer.Write((byte)_hmacEngine);
		writer.Write((byte)_engineType);
		writer.Write((byte)_blockSize);
		writer.Write((byte)_roundCount);
		writer.Write((byte)_kdfEngine);

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the MacDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MacDescription</returns>
	CEX::IO::MemoryStream* ToStream()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write((byte)_macType);
		writer.Write((short)_keySize);
		writer.Write((byte)_ivSize);
		writer.Write((byte)_hmacEngine);
		writer.Write((byte)_engineType);
		writer.Write((byte)_blockSize);
		writer.Write((byte)_roundCount);
		writer.Write((byte)_kdfEngine);

		return writer.GetStream();
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int hash = 31 * _macType;
		hash += 31 * _keySize;
		hash += 31 * _ivSize;
		hash += 31 * _hmacEngine;
		hash += 31 * _engineType;
		hash += 31 * _blockSize;
		hash += 31 * _roundCount;
		hash += 31 * _kdfEngine;

		return hash;
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(MacDescription &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}

};

NAMESPACE_COMMONEND
#endif
