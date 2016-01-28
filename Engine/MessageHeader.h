#ifndef _CEXENGINE_MESSAGEHEADER_H
#define _CEXENGINE_MESSAGEHEADER_H

#include "Common.h"
#include <algorithm>
#include "CryptoProcessingException.h"
#include "CSPPrng.h"
#include "IntUtils.h"
#include "MemoryStream.h"
#include "SeekOrigin.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

using CEX::Exception::CryptoProcessingException;

/// <summary>
/// An encrypted message file header structure. 
/// <para>Used in conjunction with the <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream"/> class.
/// KeyID and Extension values must each be 16 bytes in length. Message MAC code is optional.</para>
/// </summary>
/// 
/// <revisionHistory>
/// <revision date="2015/03/12" version="1.3.2.0">Initial release</revision>
/// <revision date="2015/07/02" version="1.4.0.0">Changes to documentation and method structure</revision>
/// </revisionHistory>
/// 
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Processing CipherStream class</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Factory.PackageFactory">VTDev.Libraries.CEXEngine.Crypto PackageFactory class</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.PackageKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures PackageKey structure</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.KeyAuthority">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures KeyAuthority structure</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription structure</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.KeyPolicies">VTDev.Libraries.CEXEngine.Crypto.Enumeration KeyPolicies Enumeration</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PackageKeyStates">VTDev.Libraries.CEXEngine.Crypto KeyStates Enumeration</seealso>
struct MessageHeader
{
private:
	static constexpr unsigned int KEYID_SIZE = 16;
	static constexpr unsigned int EXTKEY_SIZE = 16;
	static constexpr unsigned int SIZE_BASEHEADER = 32;
	static constexpr unsigned int SEEKTO_ID = 0;
	static constexpr unsigned int SEEKTO_EXT = 16;
	static constexpr unsigned int SEEKTO_HASH = 32;

	std::vector<byte> _keyID;
	std::vector<byte> _extKey;
	std::vector<byte> _msgMac;

public:

	/// <summary>
	/// The HMAC hash value of the encrypted file
	/// </summary>
	const std::vector<byte> MessageMac() const { return _msgMac; }

	/// <summary>
	/// The 16 byte key identifier
	/// </summary>
	const std::vector<byte> KeyId() { return _keyID; }

	/// <summary>
	/// The encrypted message file extension
	/// </summary>
	const std::vector<byte> ExtensionKey() { return _extKey; }


	/// <summary>
	/// MessageHeader constructor
	/// </summary>
	/// 
	/// <param name="KeyId">A unique 16 byte key ID</param>
	/// <param name="Extension">A 16 byte encrypted file extension</param>
	/// <param name="MessageHash">A message hash value, can be null</param>
	MessageHeader(std::vector<byte> &KeyId, std::vector<byte> &Extension, std::vector<byte> &MessageHash)
		:
		_keyID(KeyId),
		_extKey(Extension),
		_msgMac(MessageHash)
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
	MessageHeader(CEX::IO::MemoryStream &HeaderStream, unsigned int MacLength = 0)
		:
		_keyID(0),
		_extKey(0),
		_msgMac(0)
	{
		if (HeaderStream.Length() < SIZE_BASEHEADER)
			throw new CryptoProcessingException("MessageHeader:CTor", "MessageHeader stream is too small!");

		CEX::IO::StreamReader reader(HeaderStream);
		_keyID = reader.ReadBytes(KEYID_SIZE);
		_extKey = reader.ReadBytes(EXTKEY_SIZE);
		_msgMac = reader.ReadBytes(MacLength);
	}

	/// <summary>
	/// Initialize the MessageHeader structure using a byte array
	/// </summary>
	/// 
	/// <param name="HeaderArray">The byte array containing the MessageHeader</param>
	MessageHeader(std::vector<byte> &HeaderArray)
	{
		CEX::IO::StreamReader reader(HeaderArray);
		_keyID = reader.ReadBytes(KEYID_SIZE);
		_extKey = reader.ReadBytes(EXTKEY_SIZE);
		unsigned int len = reader.Length() - reader.Position();
		if (len > 0)
			_msgMac = reader.ReadBytes(len);
	}

	/// <summary>
	/// Clear all struct members
	/// </summary>
	void Reset()
	{
		if (_keyID.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_keyID);
		if (_extKey.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_extKey);
		if (_msgMac.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_msgMac);
	}

	/// <summary>
	/// Convert the MessageHeader structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MessageHeader</returns>
	std::vector<byte> ToBytes()
	{
		return ToStream()->ToArray();
	}

	/// <summary>
	/// Convert the MessageHeader structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MessageHeader</returns>
	CEX::IO::MemoryStream* ToStream()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());
		writer.Write(_keyID);
		writer.Write(_extKey);
		writer.Write(_msgMac);

		return writer.GetStream();
	}

	/// <summary>
	/// Get the size of a MessageHeader
	/// </summary>
	static int GetHeaderSize() { return SIZE_BASEHEADER; }

	/// <summary>
	/// Encrypt the file extension
	/// </summary>
	/// 
	/// <param name="Extension">The message file extension</param>
	/// <param name="ExtKey">Random byte array used to encrypt the extension</param>
	/// 
	/// <returns>Encrypted file extension</returns>
	static std::vector<byte> GetEncryptedExtension(std::string &Extension, std::vector<byte> &Key)
	{
		if (Extension.size() > EXTKEY_SIZE)
			throw CEX::Exception::CryptoProcessingException("MessageHeader:GetEncryptedExtension", "the extension string is too long!");
		if (Key.size() != EXTKEY_SIZE)
			throw CEX::Exception::CryptoProcessingException("MessageHeader:GetEncryptedExtension", "the key is the wrong size!");

		std::vector<byte> data(EXTKEY_SIZE);
		memcpy(&data[0], Extension.data(), Extension.length());

		// xor the buffer and hash
		for (int i = 0; i < data.size(); ++i)
			data[i] ^= Key[i];

		return data;
	}

	/// <summary>
	/// Get decrypted file extension
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// <param name="ExtKey">Random byte array used to encrypt the extension</param>
	/// 
	/// <returns>File extension</returns>
	static std::string GetDecryptedExtension(CEX::IO::MemoryStream &MessageStream, std::vector<byte> &ExtKey)
	{
		std::vector<byte> data(16);
		CEX::IO::StreamReader reader(MessageStream);

		MessageStream.Seek(SEEKTO_EXT, CEX::IO::SeekOrigin::Begin);
		data = reader.ReadBytes(EXTKEY_SIZE);

		// xor the buffer and hash
		for (int i = 0; i < data.size(); i++)
			data[i] ^= ExtKey[i];

		std::string letters(data.begin(), data.end());
		letters.erase(std::remove(letters.begin(), letters.end(), '0'), letters.end());

		return letters;
	}

	/// <summary>
	/// Get the messages unique key identifier
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// 
	/// <returns>The unique 16 byte ID of the key used to encrypt this message</returns>
	static std::vector<byte> GetKeyId(CEX::IO::MemoryStream &MessageStream)
	{
		MessageStream.Seek(SEEKTO_ID, CEX::IO::SeekOrigin::Begin);
		return CEX::IO::StreamReader(MessageStream).ReadBytes(KEYID_SIZE);
	}

	/// <summary>
	/// Get the MAC value for this file
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// <param name="MacSize">Size of the Message Authentication Code</param>
	/// 
	/// <returns>64 byte Hash value</returns>
	static std::vector<byte> GetMessageMac(CEX::IO::MemoryStream &MessageStream, int MacSize)
	{
		MessageStream.Seek(SEEKTO_HASH, CEX::IO::SeekOrigin::Begin);
		return CEX::IO::StreamReader(MessageStream).ReadBytes(MacSize);
	}

	/// <summary>
	/// Test for valid header in file
	/// </summary>
	/// 
	/// <param name="MessageStream">Stream containing a message header</param>
	/// 
	/// <returns>Valid</returns>
	static bool HasHeader(CEX::IO::MemoryStream &MessageStream)
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
	static void SetExtension(CEX::IO::MemoryStream &MessageStream, std::vector<byte> &Extension)
	{
		MessageStream.Seek(SEEKTO_EXT, CEX::IO::SeekOrigin::Begin);
		MessageStream.Write(Extension, 0, EXTKEY_SIZE);
	}

	/// <summary>
	/// Set the messages 16 byte Key ID value
	/// </summary>
	/// 
	/// <param name="MessageStream">The message stream</param>
	/// <param name="KeyID">The unique 16 byte ID of the key used to encrypt this message</param>
	static void SetKeyId(CEX::IO::MemoryStream &MessageStream, std::vector<byte> &KeyID)
	{
		MessageStream.Seek(SEEKTO_ID, CEX::IO::SeekOrigin::Begin);
		MessageStream.Write(KeyID, 0, KEYID_SIZE);
	}

	/// <summary>
	/// Set the messages MAC value
	/// </summary>
	/// 
	/// <param name="MessageStream">The message stream</param>
	/// <param name="Mac">The Message Authentication Code</param>
	static void SetMessageMac(CEX::IO::MemoryStream &MessageStream, std::vector<byte> &Mac)
	{
		MessageStream.Seek(SEEKTO_HASH, CEX::IO::SeekOrigin::Begin);
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
		if (_keyID.size() != 0)
		{
			for (int i = 0; i < _keyID.size(); i++)
				result += 31 * _keyID[i];
		}
		if (_extKey.size() != 0)
		{
			for (int i = 0; i < _extKey.size(); i++)
				result += 31 * _extKey[i];
		}
		if (_msgMac.size() != 0)
		{
			for (int i = 0; i < _msgMac.size(); ++i)
				result += 31 * _msgMac[i];
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

NAMESPACE_PROCESSINGEND
#endif