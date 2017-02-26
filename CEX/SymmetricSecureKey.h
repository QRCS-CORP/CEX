#ifndef _CEX_SECUREKEY_H
#define _CEX_SECUREKEY_H

#include "ISymmetricKey.h"

NAMESPACE_KEYSYMMETRIC

/// <summary>
/// An encrypted symmetric key container class.
/// <para>Contains encrypted keying material used for initialization of symmetric ciphers, Macs, Rngs, and Drbgs.</para>
/// </summary>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Key arrays are encrypted when the class is instantiated with data, and decrypted when accessed through the data arrays getter property functions (Key, Nonce, and Info</description></item>
/// <item><description>The key material access is limited to the initializing process, user, and computer; it is not transferrable across process or machine boundaries</description></item>
/// <item><description>Accessing the property functions from another process, user, or computer, will change the encryption key and return invalid data</description></item>
/// <item><description>Serializing a SymmetricSecureKey returns a decrypted SymmetricKey stream, deserializing a SymmetricKey stream returns an initialized SymmetricSecureKey</description></item>
/// <item><description>An optional 64bit KeySalt can be added through the constructors, this adds the salt value to system and process specific state to derive the internal encryption key</description></item>
/// <item><description>The internal key is extracted using SHA512, and the internal state is encrypted with AES256 in CTR mode</description></item>
/// </list>
/// </remarks>
class SymmetricSecureKey : public ISymmetricKey
{
private:

	bool m_isDestroyed;
	SymmetricKeySize m_keySizes;
	std::vector<byte> m_keyState;
	std::vector<byte> m_keySalt;

public:

	//~~~Public Properties~~~//

	/// <summary>
	/// Get: Return a copy of the personalization string; can used as an optional source of entropy
	/// </summary>
	virtual const std::vector<byte> Info()
	{ 
		return Extract(m_keySizes.KeySize() + m_keySizes.NonceSize(), m_keySizes.InfoSize());
	}

	/// <summary>
	/// Get: Return a copy of the primary key
	/// </summary>
	virtual const std::vector<byte> Key()
	{ 
		return Extract(0, m_keySizes.KeySize());
	}

	/// <summary>
	/// Get: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	virtual const SymmetricKeySize KeySizes() { return m_keySizes; }

	/// <summary>
	/// Get: Return a copy of the nonce
	/// </summary>
	virtual const std::vector<byte> Nonce()
	{ 
		return Extract(m_keySizes.KeySize(), m_keySizes.NonceSize());
	}

	//~~~Constructors~~~//

	/// <summary>
	/// Instantiate an empty container
	/// </summary>
	SymmetricSecureKey();

	/// <summary>
	/// Instantiate this class with an encryption key.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SymmetricSecureKey(const std::vector<byte> &Key, uint64_t KeySalt = 0);

	/// <summary>
	/// Instantiate this class with an encryption key, and nonce parameters.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, uint64_t KeySalt = 0);

	/// <summary>
	/// Instantiate this class with an encryption key, nonce, and info parameters.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, uint64_t KeySalt = 0);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SymmetricSecureKey();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a shallow copy of this SymmetricSecureKey class
	/// </summary>
	SymmetricSecureKey* Clone();

	/// <summary>
	/// Deserialize a SymmetricKey stream and return a SymmetricSecureKey
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the SymmetricKey data</param>
	/// 
	/// <returns>A populated SymmetricSecureKey container</returns>
	static SymmetricSecureKey* DeSerialize(MemoryStream &KeyStream);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Compare this SymmetricSecureKey instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Key to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	virtual bool Equals(ISymmetricKey &Obj);

	/// <summary>
	/// Decrypt a SymmetricSecureKey and serialize it as a SymmetricKey stream
	/// </summary>
	/// 
	/// <param name="KeyObj">A SymmetricSecureKey container</param>
	/// 
	/// <returns>A stream containing the serialized SymmetricKey data</returns>
	static MemoryStream* Serialize(SymmetricSecureKey &KeyObj);

private:

	std::vector<byte> Extract(size_t Offset, size_t Length);
	std::vector<byte> GetSystemKey();
	void Transform();
};

NAMESPACE_KEYSYMMETRICEND
#endif
