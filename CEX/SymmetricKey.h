#ifndef CEX_SYMMETRICKEY_H
#define CEX_SYMMETRICKEY_H

#include "ISymmetricKey.h"

NAMESPACE_CIPHER

/// <summary>
/// A symmetric key container class.
/// <para>Contains keying material used for initialization of symmetric ciphers, Macs, Rngs, and Drbgs.</para>
/// </summary>
class SymmetricKey final : public ISymmetricKey
{
private:

	std::vector<byte> m_info;
	bool m_isDestroyed;
	std::vector<byte> m_key;
	SymmetricKeySize m_keySizes;
	std::vector<byte> m_nonce;

public:

	//~~~Constructors~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricKey(const SymmetricKey&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricKey& operator=(const SymmetricKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SymmetricKey() = delete;

	/// <summary>
	/// Constructor: instantiate this class with an encryption key
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	explicit SymmetricKey(const std::vector<byte> &Key);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, and nonce parameters
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, nonce, and info parameters
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricKey() override;

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
	/// Create a copy of this SymmetricKey class
	/// </summary>
	SymmetricKey* Clone();

	/// <summary>
	/// Deserialize a SymmetricKey class.
	/// <para>The caller is resposible for destroying the return key.</para>
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the SymmetricKey data</param>
	/// 
	/// <returns>A populated SymmetricKey class</returns>
	static SymmetricKey* DeSerialize(const MemoryStream &KeyStream);

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Compare this SymmetricKey instance with another
	/// </summary>
	/// 
	/// <param name="Input">SymmetricKey to compare</param>
	/// 
	/// <returns>Returns true if equal</returns>
	bool Equals(ISymmetricKey &Input) override;

	/// <summary>
	/// Serialize a SymmetricKey class.
	/// <para>The caller is resposible for destroying the return stream.</para>
	/// </summary>
	/// 
	/// <param name="KeyObj">A SymmetricKey class</param>
	/// 
	/// <returns>A stream containing the SymmetricKey data</returns>
	static MemoryStream* Serialize(SymmetricKey &KeyObj);
};

NAMESPACE_CIPHEREND
#endif
