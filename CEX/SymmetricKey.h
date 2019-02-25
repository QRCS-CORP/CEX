#ifndef CEX_SYMMETRICKEY_H
#define CEX_SYMMETRICKEY_H

#include "ISymmetricKey.h"

NAMESPACE_CIPHER

/// <summary>
/// A symmetric key container class.
/// <para>Contains keying material used for the initialization of symmetric ciphers, Macs, Rngs, and Drbgs.</para>
/// </summary>
class SymmetricKey final : public ISymmetricKey
{
private:

	class KeyState;
	std::unique_ptr<KeyState> m_keyState;

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
	/// Constructor: instantiate this class with an cryptographic key
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	explicit SymmetricKey(const std::vector<byte> &Key);

	/// <summary>
	/// Constructor: instantiate this class with an cryptographic key, and nonce parameters
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce);

	/// <summary>
	/// Constructor: instantiate this class with an cryptographic key, nonce, and info parameters
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info);

	/// <summary>
	/// Constructor: instantiate this class with a secure-vector cryptographic key
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	explicit SymmetricKey(const SecureVector<byte> &Key);

	/// <summary>
	/// Constructor: instantiate this class with a secure-vector cryptographic key, and nonce parameters
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce);

	/// <summary>
	/// Constructor: instantiate this class with a secure-vector cryptographic key, nonce, and info parameters
	/// </summary>
	///
	/// <param name="Key">The primary cryptographic key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Return a standard-vector copy of the personalization string; can also used as an additional source of entropy in some constructions
	/// </summary>
	const std::vector<byte> Info() override;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the primary key
	/// </summary>
	const std::vector<byte> Key() override;

	/// <summary>
	/// Read Only: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	const SymmetricKeySize KeySizes() override;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the nonce; can also be used as the salt or iv
	/// </summary>
	const std::vector<byte> Nonce() override;

	/// <summary>
	/// Read Only: Return a secure-vector copy of the personalization string; can used as an optional source of entropy
	/// </summary>
	const SecureVector<byte> SecureInfo() override;

	/// <summary>
	/// Read Only: Return a secure-vector copy of the primary cryptographic key
	/// </summary>
	const SecureVector<byte> SecureKey() override;

	/// <summary>
	/// Read Only: Return a secure-vector copy of the nonce or salt value
	/// </summary>
	const SecureVector<byte> SecureNonce() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a copy of this SymmetricKey class
	/// </summary>
	SymmetricKey* Clone();

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary> 
	void Reset() override;

	//~~~Static Functions~~~//

	/// <summary>
	/// Deserialize a SymmetricKey stream and return a pointer to a SymmetricKey
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the SymmetricKey data</param>
	/// 
	/// <returns>A pointer to a populated SymmetricSecureKey container</returns>
	static SymmetricKey* DeSerialize(SecureVector<byte> &KeyStream);

	/// <summary>
	/// Serialize a SymmetricKey to a secure-vector stream
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey container</param>
	/// 
	/// <returns>A secure-vector containing the serialized SymmetricKey data</returns>
	static SecureVector<byte> Serialize(SymmetricKey &KeyParams);
};

NAMESPACE_CIPHEREND
#endif
