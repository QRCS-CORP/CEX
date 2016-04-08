#ifndef _CEXENGINE_MACKEY_H
#define _CEXENGINE_MACKEY_H

#include "Common.h"
#include "MacDescription.h"
#include "CryptoProcessingException.h"
#include "CSPPrng.h"
#include "IntUtils.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PRCSTRUCT

/// <summary>
/// The MacKey structure.
/// <para>Used in conjunction with the <see cref="CEX::Crypto.Processing::MacStream"/> class. 
/// This structure is used as the header for a Mac key file.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of populating a MacKey structure:</description>
/// <code>
/// MacKey mk = new MacKey(MacDescription, [Keyid]);
/// </code>
/// </example>
///
/// <seealso cref="CEX::Common::MacDescription"/>
/// <seealso cref="CEX::Crypto.Processing::MacStream"/>
struct MacKey
{
private:
	static constexpr uint MACDSC_SIZE = 10;
	static constexpr uint KEYUID_SIZE = 16;
	static constexpr uint MACKEY_SIZE = 16;
	static constexpr uint MACDSC_SEEK = 0;
	static constexpr uint KEYUID_SEEK = MACDSC_SIZE;

	std::vector<byte> _keyId;
	CEX::Common::MacDescription _macDsc;

public:

	/// <summary>
	/// The MacDescription structure containing a complete description of the Mac instance
	/// </summary>
	CEX::Common::MacDescription Description() const { return _macDsc; }

	/// <summary>
	/// The unique 16 byte ID field used to identify this key.
	/// </summary>
	const std::vector<byte> &KeyId() { return _keyId; }

	/// <summary>
	/// Default constructor
	/// </summary>
	MacKey()
		:
		_macDsc(),
		_keyId(0)
	{
	}

	/// <summary>
	/// MacKey structure constructor.
	/// <para>KeyID and ExtRandom values must each be 16 bytes in length.
	/// If they are not specified they will be populated automatically.</para>
	/// </summary>
	/// 
	/// <param name="Description">The MacDescription structure containing a complete description of the Mac instance</param>
	/// <param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if either the KeyId or ExtensionKey fields are null or invalid</exception>
	MacKey(CEX::Common::MacDescription &Description, std::vector<byte> &KeyId)
		:
		_macDsc(Description),
		_keyId(0)
	{
		if (KeyId.size() == 0)
		{
			CEX::Prng::CSPPrng rnd;
			_keyId = rnd.GetBytes(KEYUID_SIZE);
		}
		else if (KeyId.size() != KEYUID_SIZE)
		{
			throw new CEX::Exception::CryptoProcessingException("CipherKey:CTor", "The MacKey must be exactly 16 bytes!");
		}
		else
		{
			_keyId = KeyId;
		}
	}

	/// <summary>
	/// Initialize the MacKey structure using a Stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The Stream containing the MacKey</param>
	explicit MacKey(CEX::IO::MemoryStream &KeyStream)
		:
		_keyId(0)
	{
		CEX::IO::StreamReader reader(KeyStream);

		_macDsc = CEX::Common::MacDescription(reader.ReadBytes(CEX::Common::MacDescription::GetHeaderSize()));
		_keyId = reader.ReadBytes(KEYUID_SIZE);
	}

	/// <summary>
	/// Initialize the MacKey structure using a byte array
	/// </summary>
	/// 
	/// <param name="KeyArray">The byte array containing the MacKey</param>
	explicit MacKey(std::vector<byte> &KeyArray)
		:
		_keyId(0)
	{
		CEX::IO::MemoryStream ms = CEX::IO::MemoryStream(KeyArray);
		CEX::IO::StreamReader reader(ms);

		_macDsc = CEX::Common::MacDescription(reader.ReadBytes(CEX::Common::MacDescription::GetHeaderSize()));
		_keyId = reader.ReadBytes(KEYUID_SIZE);
	}

	/// <summary>
	/// Reset all members of the MacKey structure, including the MacDescription
	/// </summary>
	void Reset()
	{
		_macDsc.Reset();
		if (_keyId.size() != 0)
			CEX::Utility::IntUtils::ClearVector(_keyId);
	}

	/// <summary>
	/// Convert the MacKey structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MacKey</returns>
	std::vector<byte> ToBytes()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write(_macDsc.ToBytes());
		writer.Write(_keyId);

		return writer.GetBytes();
	}

	/// <summary>
	/// Convert the MacKey structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MacKey</returns>
	CEX::IO::MemoryStream* ToStream()
	{
		CEX::IO::StreamWriter writer(GetHeaderSize());

		writer.Write(_macDsc.ToBytes());
		writer.Write(_keyId);

		return writer.GetStream();
	}

	/// <summary>
	/// Get the header Size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return MACDSC_SIZE + KEYUID_SIZE;
	}

	/// <summary>
	/// Get the Mac description header
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a key package</param>
	/// 
	/// <returns>MacDescription structure</returns>
	static CEX::Common::MacDescription* GetCipherDescription(CEX::IO::MemoryStream &KeyStream)
	{
		KeyStream.Seek(MACDSC_SEEK, CEX::IO::SeekOrigin::Begin);
		return new CEX::Common::MacDescription(KeyStream);
	}

	/// <summary>
	/// Get the key id (16 bytes)
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a Mac key</param>
	/// 
	/// <returns>The file extension key</returns>
	static std::vector<byte> GetKeyId(CEX::IO::MemoryStream &KeyStream)
	{
		KeyStream.Seek(KEYUID_SEEK, CEX::IO::SeekOrigin::Begin);
		return CEX::IO::StreamReader(KeyStream).ReadBytes(KEYUID_SIZE);
	}

	/// <summary>
	/// Set the MacDescription structure
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a key package</param>
	/// <param name="Description">The MacDescription structure</param>
	static void SetCipherDescription(CEX::IO::MemoryStream &KeyStream, CEX::Common::MacDescription &Description)
	{
		KeyStream.Seek(MACDSC_SEEK, CEX::IO::SeekOrigin::Begin);
		KeyStream.Write(Description.ToBytes(), 0, MACDSC_SIZE);
	}

	/// <summary>
	/// Set the Key Id
	/// </summary>
	/// 
	/// <param name="KeyStream">The stream containing a Mac key</param>
	/// <param name="KeyId">Array of 16 bytes containing the key id</param>
	static void SetKeyId(CEX::IO::MemoryStream &KeyStream, std::vector<byte> &KeyId)
	{
		KeyStream.Seek(KEYUID_SEEK, CEX::IO::SeekOrigin::Begin);
		KeyStream.Write(KeyId, 0, KEYUID_SIZE);
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = _macDsc.GetHashCode();
		for (size_t i = 0; i < _keyId.size(); ++i)
			result += (31 * _keyId[i]);

		return result;
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(MacKey &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}
};

NAMESPACE_PRCSTRUCTEND
#endif
