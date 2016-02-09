#ifndef _CEXENGINE_CIPHERKEY_H
#define _CEXENGINE_CIPHERKEY_H

#include "Common.h"
#include "CipherDescription.h"
#include "CryptoProcessingException.h"
#include "CSPPrng.h"
#include "IntUtils.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PRCSTRUCT

/// <summary>
/// The CipherKey structure.
/// <para>Used in conjunction with the CipherStream class. 
/// This structure is used as the header for a single use key and vector set.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of populating a CipherKey structure:</description>
/// <code>
/// CipherKey ck = new CipherKey(description);
/// </code>
/// </example>
///
/// <seealso cref="CEX::Common::CipherDescription"/>
struct CipherKey
{
private:
	static constexpr unsigned int KEYID_SIZE = 16;
	static constexpr unsigned int EXTKEY_SIZE = 16;
	static constexpr unsigned int DESC_SIZE = 11;
	static constexpr unsigned long KEYID_SEEK = 0;
	static constexpr unsigned long EXTKEY_SEEK = DESC_SIZE;
	static constexpr unsigned long DESC_SEEK = DESC_SIZE + EXTKEY_SIZE;

	std::vector<byte> _keyID;
	std::vector<byte> _extKey;
	CEX::Common::CipherDescription _cprDsc;

public:

	/// <summary>
	/// The <see cref="CEX::Common::CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance
	/// </summary>
	CEX::Common::CipherDescription Description() const { return _cprDsc; }

	/// <summary>
	/// The unique 16 byte ID field used to identify this key. A null value auto generates this field
	/// </summary>
	const std::vector<byte> &KeyId() { return _keyID; }

	/// <summary>
	/// An array of random bytes used to encrypt a message file extension. A null value auto generates this field
	/// </summary>
	const std::vector<byte> &ExtensionKey() { return _extKey; }

	/// <summary>
	/// Default constructor
	/// </summary>
	CipherKey()
		:
		_cprDsc(),
		_extKey(0),
		_keyID(0)
	{
	}

	/// <summary>
	/// CipherKey structure constructor.
	/// <para>KeyID and ExtRandom values must each be 16 bytes in length.
	/// If they are not specified they will be populated automatically.</para>
	/// </summary>
	/// 
	/// <param name="Description">The <see cref="CEX::Common::CipherDescription">CipherDescription</see> structure containing a complete description of the cipher instance</param>
	/// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field</param>
	/// <param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if either the KeyId or ExtensionKey fields are null or invalid</exception>
	CipherKey(CEX::Common::CipherDescription &Description, std::vector<byte> &KeyId, std::vector<byte> &ExtensionKey)
		:
		_cprDsc(Description),
		_extKey(0),
		_keyID(0)
	{

		_cprDsc = Description;

		if (KeyId.size() == 0)
		{
			CEX::Prng::CSPPrng rnd;
			_keyID = rnd.GetBytes(KEYID_SIZE);
		}
		else if (KeyId.size() != KEYID_SIZE)
		{
			throw new CEX::Exception::CryptoProcessingException("CipherKey:CTor", "The KeyId must be exactly 16 bytes!");
		}
		else
		{
			_keyID = KeyId;
		}

		if (ExtensionKey.size() == 0)
		{
			CEX::Prng::CSPPrng rnd;
			_extKey = rnd.GetBytes(EXTKEY_SIZE);
		}
		else if (ExtensionKey.size() != EXTKEY_SIZE)
		{
			throw new CEX::Exception::CryptoProcessingException("CipherKey:CTor", "The random extension field must be exactly 16 bytes!");
		}
		else
		{
			_extKey = ExtensionKey;
		}
	}

	/// <summary>
	/// Initialize the CipherKey structure using a Stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The Stream containing the CipherKey</param>
	CipherKey(CEX::IO::MemoryStream &KeyStream)
		:
		_extKey(0),
		_keyID(0)
	{
		CEX::IO::StreamReader reader(KeyStream);
		_keyID = reader.ReadBytes(KEYID_SIZE);
		_extKey = reader.ReadBytes(EXTKEY_SIZE);
		_cprDsc = CEX::Common::CipherDescription(reader.ReadBytes(CEX::Common::CipherDescription::GetHeaderSize()));
	}

	/// <summary>
	/// Initialize the CipherKey structure using a byte array
	/// </summary>
	/// 
	/// <param name="KeyArray">The byte array containing the CipherKey</param>
	CipherKey(std::vector<byte> &KeyArray)
		:
		_extKey(0),
		_keyID(0)
	{
		CEX::IO::MemoryStream ms = CEX::IO::MemoryStream(KeyArray);
		CEX::IO::StreamReader reader(ms);
		_keyID = reader.ReadBytes(KEYID_SIZE);
		_extKey = reader.ReadBytes(EXTKEY_SIZE);
		_cprDsc = CEX::Common::CipherDescription(reader.ReadBytes(CEX::Common::CipherDescription::GetHeaderSize()));
	}

	/// <summary>
	/// Reset all members of the CipherKey structure, including the CipherDescription
	/// </summary>
	void Reset()
	{
		_cprDsc.Reset();
		if (_extKey.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_extKey);
		if (_keyID.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_keyID);
	}

	/// <summary>
	/// Convert the CipherKey structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the CipherKey</returns>
	std::vector<byte> ToBytes()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());
		writer.Write(_keyID);
		writer.Write(_extKey);
		writer.Write(_cprDsc.ToBytes());

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the CipherKey structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the CipherKey</returns>
	CEX::IO::MemoryStream* ToStream()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());
		writer.Write(_keyID);
		writer.Write(_extKey);
		writer.Write(_cprDsc.ToBytes());

		return writer.GetStream();
	}

	/// <summary>
	/// Get the header Size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return DESC_SIZE + KEYID_SIZE + EXTKEY_SIZE;
	}

	/// <summary>
	/// Get the cipher description header
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a key package</param>
	/// 
	/// <returns>CipherDescription structure</returns>
	static CEX::Common::CipherDescription* GetCipherDescription(CEX::IO::MemoryStream &KeyStream)
	{
		KeyStream.Seek(DESC_SEEK, CEX::IO::SeekOrigin::Begin);
		return new CEX::Common::CipherDescription(KeyStream);
	}

	/// <summary>
	/// Get the extension key (16 bytes)
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing the cipher key</param>
	/// 
	/// <returns>The file extension key</returns>
	static std::vector<byte> GetExtensionKey(CEX::IO::MemoryStream &KeyStream)
	{
		KeyStream.Seek(EXTKEY_SEEK, CEX::IO::SeekOrigin::Begin);
		return CEX::IO::StreamReader(KeyStream).ReadBytes(EXTKEY_SIZE);
	}

	/// <summary>
	/// Get the key id (16 bytes)
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// 
	/// <returns>The file extension key</returns>
	static std::vector<byte> GetKeyId(CEX::IO::MemoryStream &KeyStream)
	{
		KeyStream.Seek(KEYID_SEEK, CEX::IO::SeekOrigin::Begin);
		return CEX::IO::StreamReader(KeyStream).ReadBytes(KEYID_SIZE);
	}

	/// <summary>
	/// Set the CipherDescription structure
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a key package</param>
	/// <param name="Description">The CipherDescription structure</param>
	static void SetCipherDescription(CEX::IO::MemoryStream &KeyStream, CEX::Common::CipherDescription &Description)
	{
		KeyStream.Seek(DESC_SEEK, CEX::IO::SeekOrigin::Begin);
		KeyStream.Write(Description.ToBytes(), 0, DESC_SIZE);
	}

	/// <summary>
	/// Set the ExtensionKey
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// <param name="ExtensionKey">Array of 16 bytes containing the ExtensionKey</param>
	static void SetExtensionKey(CEX::IO::MemoryStream &KeyStream, std::vector<byte> &ExtensionKey)
	{
		KeyStream.Seek(EXTKEY_SEEK, CEX::IO::SeekOrigin::Begin);
		KeyStream.Write(ExtensionKey, 0, EXTKEY_SIZE);
	}

	/// <summary>
	/// Set the Key Id
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// <param name="KeyId">Array of 16 bytes containing the key id</param>
	static void SetKeyId(CEX::IO::MemoryStream &KeyStream, std::vector<byte> &KeyId)
	{
		KeyStream.Seek(KEYID_SEEK, CEX::IO::SeekOrigin::Begin);
		KeyStream.Write(KeyId, 0, KEYID_SIZE);
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = _cprDsc.GetHashCode();
		for (unsigned int i = 0; i < _keyID.size(); ++i)
			result += (int)(31 * _keyID[i]);
		for (unsigned int i = 0; i < _extKey.size(); ++i)
			result += (int)(31 * _extKey[i]);

		return result;
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(CipherKey &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}
};

NAMESPACE_PRCSTRUCTEND
#endif
