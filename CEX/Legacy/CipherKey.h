#ifndef _CEXENGINE_CIPHERKEY_H
#define _CEXENGINE_CIPHERKEY_H

#include "CexDomain.h"
#include "ArrayUtils.h"
#include "CipherDescription.h"
#include "CryptoProcessingException.h"
#include "SecureRandom.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PRCSTRUCT

using Processing::Structure::CipherDescription;
using Prng::SecureRandom;
using Exception::CryptoProcessingException;
using IO::MemoryStream;
using IO::SeekOrigin;
using IO::StreamReader;
using IO::StreamWriter;

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
struct CipherKey
{
private:
	static constexpr uint KEYID_SIZE = 16;
	static constexpr uint EXTKEY_SIZE = 16;
	static constexpr uint DESC_SIZE = 11;
	static constexpr unsigned long KEYID_SEEK = 0;
	static constexpr unsigned long EXTKEY_SEEK = DESC_SIZE;
	static constexpr unsigned long DESC_SEEK = DESC_SIZE + EXTKEY_SIZE;

	std::vector<byte> m_keyID;
	std::vector<byte> m_extKey;
	CipherDescription m_cprDsc;

public:

	/// <summary>
	/// The CipherDescription structure containing a complete description of the cipher instance
	/// </summary>
	CipherDescription Description() const { return m_cprDsc; }

	/// <summary>
	/// The unique 16 byte ID field used to identify this key.
	/// </summary>
	const std::vector<byte> &KeyId() { return m_keyID; }

	/// <summary>
	/// An array of random bytes used to encrypt a message file extension.
	/// </summary>
	const std::vector<byte> &ExtensionKey() { return m_extKey; }

	/// <summary>
	/// Default constructor
	/// </summary>
	CipherKey()
		:
		m_cprDsc(),
		m_extKey(0),
		m_keyID(0)
	{
	}

	/// <summary>
	/// CipherKey structure constructor.
	/// <para>KeyID and ExtRandom values must each be 16 bytes in length.
	/// If they are not specified they will be populated automatically.</para>
	/// </summary>
	/// 
	/// <param name="Description">The CipherDescriptionstructure containing a complete description of the cipher instance</param>
	/// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field</param>
	/// <param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if either the KeyId or ExtensionKey fields are null or invalid</exception>
	CipherKey(CipherDescription &Description, std::vector<byte> &KeyId, std::vector<byte> &ExtensionKey)
		:
		m_cprDsc(Description),
		m_extKey(0),
		m_keyID(0)
	{
		if (KeyId.size() == 0)
		{
			SecureRandom rnd;
			m_keyID = rnd.GetBytes(KEYID_SIZE);
		}
		else if (KeyId.size() != KEYID_SIZE)
		{
			throw CryptoProcessingException("CipherKey:CTor", "The KeyId must be exactly 16 bytes!");
		}
		else
		{
			m_keyID = KeyId;
		}

		if (ExtensionKey.size() == 0)
		{
			SecureRandom rnd;
			m_extKey = rnd.GetBytes(EXTKEY_SIZE);
		}
		else if (ExtensionKey.size() != EXTKEY_SIZE)
		{
			throw CryptoProcessingException("CipherKey:CTor", "The random extension field must be exactly 16 bytes!");
		}
		else
		{
			m_extKey = ExtensionKey;
		}
	}

	/// <summary>
	/// Initialize the CipherKey structure using a Stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The Stream containing the CipherKey</param>
	explicit CipherKey(MemoryStream &KeyStream)
		:
		m_extKey(0),
		m_keyID(0)
	{
		StreamReader reader(KeyStream);
		m_keyID = reader.ReadBytes(KEYID_SIZE);
		m_extKey = reader.ReadBytes(EXTKEY_SIZE);
		m_cprDsc = CipherDescription(reader.ReadBytes(CipherDescription::GetHeaderSize()));
	}

	/// <summary>
	/// Initialize the CipherKey structure using a byte array
	/// </summary>
	/// 
	/// <param name="KeyArray">The byte array containing the CipherKey</param>
	explicit CipherKey(std::vector<byte> &KeyArray)
		:
		m_extKey(0),
		m_keyID(0)
	{
		MemoryStream ms = MemoryStream(KeyArray);
		StreamReader reader(ms);
		m_keyID = reader.ReadBytes(KEYID_SIZE);
		m_extKey = reader.ReadBytes(EXTKEY_SIZE);
		m_cprDsc = CipherDescription(reader.ReadBytes(CipherDescription::GetHeaderSize()));
	}

	/// <summary>
	/// Reset all members of the CipherKey structure, including the CipherDescription
	/// </summary>
	void Reset()
	{
		m_cprDsc.Reset();
		if (m_extKey.size() != 0)
			Utility::ArrayUtils::ClearVector(m_extKey);
		if (m_keyID.size() != 0)
			Utility::ArrayUtils::ClearVector(m_keyID);
	}

	/// <summary>
	/// Convert the CipherKey structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the CipherKey</returns>
	std::vector<byte> ToBytes()
	{
		StreamWriter writer(GetHeaderSize());
		writer.Write(m_keyID);
		writer.Write(m_extKey);
		std::vector<byte> cpr = m_cprDsc.ToBytes();
		writer.Write(cpr);

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the CipherKey structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the CipherKey</returns>
	MemoryStream* ToStream()
	{
		StreamWriter writer(GetHeaderSize());
		writer.Write(m_keyID);
		writer.Write(m_extKey);
		std::vector<byte> cpr = m_cprDsc.ToBytes();
		writer.Write(cpr);

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
	static CipherDescription* GetCipherDescription(MemoryStream &KeyStream)
	{
		KeyStream.Seek(DESC_SEEK, SeekOrigin::Begin);
		return new CipherDescription(KeyStream);
	}

	/// <summary>
	/// Get the extension key (16 bytes)
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing the cipher key</param>
	/// 
	/// <returns>The file extension key</returns>
	static std::vector<byte> GetExtensionKey(MemoryStream &KeyStream)
	{
		KeyStream.Seek(EXTKEY_SEEK, SeekOrigin::Begin);
		return StreamReader(KeyStream).ReadBytes(EXTKEY_SIZE);
	}

	/// <summary>
	/// Get the key id (16 bytes)
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// 
	/// <returns>The file extension key</returns>
	static std::vector<byte> GetKeyId(MemoryStream &KeyStream)
	{
		KeyStream.Seek(KEYID_SEEK, SeekOrigin::Begin);
		return StreamReader(KeyStream).ReadBytes(KEYID_SIZE);
	}

	/// <summary>
	/// Set the CipherDescription structure
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a key package</param>
	/// <param name="Description">The CipherDescription structure</param>
	static void SetCipherDescription(MemoryStream &KeyStream, CipherDescription &Description)
	{
		KeyStream.Seek(DESC_SEEK, SeekOrigin::Begin);
		KeyStream.Write(Description.ToBytes(), 0, DESC_SIZE);
	}

	/// <summary>
	/// Set the ExtensionKey
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// <param name="ExtensionKey">Array of 16 bytes containing the ExtensionKey</param>
	static void SetExtensionKey(MemoryStream &KeyStream, std::vector<byte> &ExtensionKey)
	{
		KeyStream.Seek(EXTKEY_SEEK, SeekOrigin::Begin);
		KeyStream.Write(ExtensionKey, 0, EXTKEY_SIZE);
	}

	/// <summary>
	/// Set the Key Id
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a cipher key</param>
	/// <param name="KeyId">Array of 16 bytes containing the key id</param>
	static void SetKeyId(MemoryStream &KeyStream, std::vector<byte> &KeyId)
	{
		KeyStream.Seek(KEYID_SEEK, SeekOrigin::Begin);
		KeyStream.Write(KeyId, 0, KEYID_SIZE);
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = m_cprDsc.GetHashCode();
		for (size_t i = 0; i < m_keyID.size(); ++i)
			result += (31 * m_keyID[i]);
		for (size_t i = 0; i < m_extKey.size(); ++i)
			result += (31 * m_extKey[i]);

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
