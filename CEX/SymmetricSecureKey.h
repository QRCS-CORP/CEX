#ifndef CEX_SYMMETRICSECUREKEY_H
#define CEX_SYMMETRICSECUREKEY_H

#include "ISymmetricKey.h"

NAMESPACE_SYMMETRICKEY

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
class SymmetricSecureKey final : public ISymmetricKey
{
private:

	bool m_isDestroyed;
	SymmetricKeySize m_keySizes;
	std::vector<byte> m_keyState;
	std::vector<byte> m_keySalt;

public:

	//~~~Constructors~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricSecureKey(const SymmetricSecureKey&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricSecureKey& operator=(const SymmetricSecureKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SymmetricSecureKey() = delete;

	/// <summary>
	/// Constructor: instantiate this class with an encryption key.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	explicit SymmetricSecureKey(const std::vector<byte> &Key, ulong KeySalt = 0);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, and nonce parameters.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, ulong KeySalt = 0);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, nonce, and info parameters.
	/// <para>The optional KeySalt value can be added to the seed material used by the internal encryption key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, ulong KeySalt = 0);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricSecureKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Return a copy of the personalization string; can used as an optional source of entropy
	/// </summary>
	const std::vector<byte> Info() override;

	/// <summary>
	/// Read Only: Return a copy of the primary key
	/// </summary>
	const std::vector<byte> Key() override;

	/// <summary>
	/// Read Only: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	const SymmetricKeySize KeySizes() override;

	/// <summary>
	/// Read Only: Return a copy of the nonce
	/// </summary>
	const std::vector<byte> Nonce() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a copy of this SymmetricSecureKey class
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
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Compare this SymmetricSecureKey instance with another
	/// </summary>
	/// 
	/// <param name="Input">Key to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	bool Equals(ISymmetricKey &Input) override;

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

NAMESPACE_SYMMETRICKEYEND
#endif
