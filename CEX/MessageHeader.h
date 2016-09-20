#ifndef _CEXENGINE_MESSAGEHEADER_H
#define _CEXENGINE_MESSAGEHEADER_H

#include "Common.h"
#include <algorithm>
#include "CryptoProcessingException.h"
#include "IntUtils.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PRCSTRUCT

using CEX::Exception::CryptoProcessingException;
using CEX::Utility::IntUtils;
using CEX::IO::MemoryStream;
using CEX::IO::SeekOrigin;
using CEX::IO::StreamReader;
using CEX::IO::StreamWriter;

/// <summary>
/// An encrypted message file header structure. 
/// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/> class.
/// KeyID and Extension values must each be 16 bytes in length. Message MAC code is optional.</para>
/// </summary>
struct MessageHeader
{
private:
	static constexpr uint KEYID_SIZE = 16;
	static constexpr uint EXTKEY_SIZE = 16;
	static constexpr uint SIZE_BASEHEADER = 32;
	static constexpr uint SEEKTO_ID = 0;
	static constexpr uint SEEKTO_EXT = 16;
	static constexpr uint SEEKTO_HASH = 32;

	std::vector<byte> m_keyID;
	std::vector<byte> m_extKey;
	std::vector<byte> m_msgMac;

public:

	/// <summary>
	/// The HMAC hash value of the encrypted file
	/// </summary>
	const std::vector<byte> &MessageMac() const { return m_msgMac; }

	/// <summary>
	/// The 16 byte key identifier
	/// </summary>
	const std::vector<byte> &KeyId() const { return m_keyID; }

	/// <summary>
	/// The encrypted message file extension
	/// </summary>
	const std::vector<byte> &ExtensionKey() const { return m_extKey; }

	/// <summary>
	/// Default constructor
	/// </summary>
	MessageHeader() 
		:
		m_keyID(0),
		m_extKey(0),
		m_msgMac(0)
	{}

	/// <summary>
	/// MessageHeader constructor
	/// </summary>
	/// 
	/// <param name="KeyId">A unique 16 byte key ID</param>
	/// <param name="Extension">A 16 byte encrypted file extension</param>
	/// <param name="MessageHash">A message hash value, can be null</param>
	MessageHeader(std::vector<byte> &KeyId, std::vector<byte> &Extension, std::vector<byte> &MessageHash)
		:
		m_keyID(KeyId),
		m_extKey(Extension),
		m_msgMac(MessageHash)
	{
	}

	/// <summary>
	/// Initialize the MessageHeader structure using a Stream
	/// </summary>
	/// 
	/// <param name="HeaderStream">The Stream containing the MessageHeader</param>
	/// <param name="MacLength">Length in bytes of the Message Authentication Code; must align to MacLength property in <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey"/></param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the DataStream is too small</exception>
	MessageHeader(MemoryStream &HeaderStream, uint MacLength = 0)
		:
		m_keyID(0),
		m_extKey(0),
		m_msgMac(0)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (HeaderStream.Length() < SIZE_BASEHEADER)
			throw CryptoProcessingException("MessageHeader:CTor", "MessageHeader stream is too small!");
#endif
		StreamReader reader(HeaderStream);
		m_keyID = reader.ReadBytes(KEYID_SIZE);
		m_extKey = reader.ReadBytes(EXTKEY_SIZE);
		if (MacLength > 0)
			m_msgMac = reader.ReadBytes(MacLength);
	}

	/// <summary>
	/// Initialize the MessageHeader structure using a byte array
	/// </summary>
	/// 
	/// <param name="HeaderArray">The byte array containing the MessageHeader</param>
	explicit MessageHeader(std::vector<byte> &HeaderArray)
	{
		MemoryStream ms = MemoryStream(HeaderArray);
		StreamReader reader(ms);
		m_keyID = reader.ReadBytes(KEYID_SIZE);
		m_extKey = reader.ReadBytes(EXTKEY_SIZE);
		size_t len = (reader.Length() - reader.Position());
		if (len > 0)
			m_msgMac = reader.ReadBytes(len);
	}

	/// <summary>
	/// Clear all struct members
	/// </summary>
	void Reset()
	{
		if (m_keyID.size() != 0)
			IntUtils::ClearVector(m_keyID);
		if (m_extKey.size() != 0)
			IntUtils::ClearVector(m_extKey);
		if (m_msgMac.size() != 0)
			IntUtils::ClearVector(m_msgMac);
	}

	/// <summary>
	/// Convert the MessageHeader structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MessageHeader</returns>
	std::vector<byte> ToBytes()
	{
		StreamWriter writer(GetHeaderSize());
		writer.Write(m_keyID);
		writer.Write(m_extKey);
		if (m_msgMac.size() > 0)
			writer.Write(m_msgMac);

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the MessageHeader structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MessageHeader</returns>
	MemoryStream* ToStream()
	{
		StreamWriter writer(GetHeaderSize());
		writer.Write(m_keyID);
		writer.Write(m_extKey);
		if (m_msgMac.size() > 0)
			writer.Write(m_msgMac);

		return writer.GetStream();
	}

	/// <summary>
	/// Get the size of a MessageHeader
	/// </summary>
	static uint GetHeaderSize() { return SIZE_BASEHEADER; }

	/// <summary>
	/// Get decrypted file extension
	/// </summary>
	/// 
	/// <param name="Extension">The encrypted file extension</param>
	/// <param name="Key">Random byte array used to encrypt the extension</param>
	/// 
	/// <returns>File extension</returns>
	static std::string DecryptExtension(const std::vector<byte> &Extension, const std::vector<byte> &Key)
	{
		std::vector<byte> data(Extension.size());
		memcpy(&data[0], &Extension[0], Extension.size());
		// xor the buffer and hash
		for (size_t i = 0; i < Extension.size(); i++)
			data[i] ^= Key[i];

		std::string letters(data.begin(), data.end());
		letters.erase(std::remove(letters.begin(), letters.end(), '\0'), letters.end());

		return letters;
	}

	/// <summary>
	/// Encrypt the file extension
	/// </summary>
	/// 
	/// <param name="Extension">The message file extension</param>
	/// <param name="Key">Random byte array used to encrypt the extension</param>
	/// 
	/// <returns>Encrypted file extension</returns>
	static std::vector<byte> EncryptExtension(const std::string &Extension, const std::vector<byte> &Key)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Extension.size() > EXTKEY_SIZE)
			throw CryptoProcessingException("MessageHeader:GetEncryptedExtension", "the extension string is too long!");
		if (Key.size() != EXTKEY_SIZE)
			throw CryptoProcessingException("MessageHeader:GetEncryptedExtension", "the key is the wrong size!");
#endif

		std::vector<byte> data(EXTKEY_SIZE);
		memcpy(&data[0], Extension.data(), Extension.length());

		// xor the buffer and hash
		for (size_t i = 0; i < data.size(); ++i)
			data[i] ^= Key[i];

		return data;
	}

	/// <summary>
	/// Get the file extension key
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// 
	/// <returns>The 16 byte extension key field</returns>
	static std::vector<byte> GetExtensionKey(MemoryStream &MessageStream)
	{
		MessageStream.Seek(SEEKTO_EXT, SeekOrigin::Begin);
		return StreamReader(MessageStream).ReadBytes(EXTKEY_SIZE);
	}

	/// <summary>
	/// Get the messages unique key identifier
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// 
	/// <returns>The unique 16 byte ID of the key used to encrypt this message</returns>
	static std::vector<byte> GetKeyId(MemoryStream &MessageStream)
	{
		MessageStream.Seek(SEEKTO_ID, SeekOrigin::Begin);
		return StreamReader(MessageStream).ReadBytes(KEYID_SIZE);
	}

	/// <summary>
	/// Get the MAC value for this file
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// <param name="MacKeySize">Size of the Message Authentication Code key</param>
	/// 
	/// <returns>64 byte Hash value</returns>
	static std::vector<byte> GetMessageMac(MemoryStream &MessageStream, int MacKeySize)
	{
		MessageStream.Seek(SEEKTO_HASH, SeekOrigin::Begin);
		return StreamReader(MessageStream).ReadBytes(MacKeySize);
	}

	/// <summary>
	/// Test for valid header in file
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// 
	/// <returns>Valid</returns>
	static bool HasHeader(MemoryStream &MessageStream)
	{
		// not a guarantee of valid header
		return MessageStream.Length() >= GetHeaderSize();
	}

	/// <summary>
	/// Set the messages 16 byte Key ID value
	/// </summary>
	/// 
	/// <param name="MessageStream">The message stream</param>
	/// <param name="Extension">The message file extension</param>
	static void SetExtensionKey(MemoryStream &MessageStream, std::vector<byte> &Extension)
	{
		MessageStream.Seek(SEEKTO_EXT, SeekOrigin::Begin);
		MessageStream.Write(Extension, 0, EXTKEY_SIZE);
	}

	/// <summary>
	/// Set the messages 16 byte Key ID value
	/// </summary>
	/// 
	/// <param name="MessageStream">The message stream</param>
	/// <param name="KeyID">The unique 16 byte ID of the key used to encrypt this message</param>
	static void SetKeyId(MemoryStream &MessageStream, std::vector<byte> &KeyID)
	{
		MessageStream.Seek(SEEKTO_ID, SeekOrigin::Begin);
		MessageStream.Write(KeyID, 0, KEYID_SIZE);
	}

	/// <summary>
	/// Set the messages MAC value
	/// </summary>
	/// 
	/// <param name="MessageStream">The message stream</param>
	/// <param name="Mac">The Message Authentication Code</param>
	static void SetMessageMac(MemoryStream &MessageStream, std::vector<byte> &Mac)
	{
		MessageStream.Seek(SEEKTO_HASH, SeekOrigin::Begin);
		MessageStream.Write(Mac, 0, Mac.size());
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = 1;
		if (m_keyID.size() != 0)
		{
			for (size_t i = 0; i < m_keyID.size(); i++)
				result += (31 * m_keyID[i]);
		}
		if (m_extKey.size() != 0)
		{
			for (size_t i = 0; i < m_extKey.size(); i++)
				result += (31 * m_extKey[i]);
		}
		if (m_msgMac.size() != 0)
		{
			for (size_t i = 0; i < m_msgMac.size(); ++i)
				result += (31 * m_msgMac[i]);
		}

		return result;
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(MessageHeader &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}
};

NAMESPACE_PRCSTRUCTEND
#endif