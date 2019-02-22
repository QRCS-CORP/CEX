#ifndef CEX_SYMMETRICSECUREKEY_H
#define CEX_SYMMETRICSECUREKEY_H

#include "ISymmetricKey.h"
#include "CryptoAuthenticationFailure.h"
#include "IStreamCipher.h"
#include "SecurityPolicy.h"
#include "SymmetricKey.h"

NAMESPACE_CIPHER

using Exception::CryptoAuthenticationFailure;
using Cipher::Stream::IStreamCipher;
using Enumeration::SecurityPolicy;

/// <summary>
/// An encrypted and authenticated Symmetric key container.
/// <para>Contains the internally encrypted, and optionally authenticated secure-vector Key, Nonce, and Info parameters.
/// Internal parameter storage uses a secure-vector encrypted with an optionally authenticated threefish cipher instance. \n
/// The authentication option, and the ciphers strength (256/512/1024), are set through the SecurityPolicy enumeration in the class constructors. \n
/// The cipher key is derived from system information and various process handles along with a salt value, this is processed by an instance of cSHAKE to produce the cipher key. \n
/// The vectors containing the symmetric keying material can be accessed through a secure-vector copy using SecureKey, SecureNonce or SecureInfo accessors, or return a standard-vector copy using the Key, Nonce and Info accessors.<para>
/// </summary>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Key arrays are encrypted when the class is instantiated with data, and decrypted when accessed through the data arrays getter property functions (Key, Nonce, and Info, or, SecureKey, SecureNonce and SecureInfo)</description></item>
/// <item><description>The key material access is limited to the initializing process, user, and computer; it is not transferrable across processes, machine, or domain boundaries</description></item>
/// <item><description>Accessing the property functions from another process, user, or computer, will change the encryption key and return invalid data</description></item>
/// <item><description>Serializing a SymmetricSecureKey returns a decrypted SymmetricKey stream, deserializing a SymmetricKey stream returns an initialized SymmetricKey</description></item>
/// <item><description>An optional KeySalt can be added through the constructors, this adds the salt value to system and process specific state to derive the internal encryption key</description></item>
/// <item><description>The internal key is extracted using cSHAKE, and the internal state is encrypted using a Threefish cipher instance</description></item>
/// <item><description>Authentication options and cipher strength are defined by the constructors SecurityPolicy enumeration, the default is non-authenticated Threefish-256</description></item>
/// </list>
/// </remarks>
class SymmetricSecureKey final : public ISymmetricKey
{
private:

	static const std::string CLASS_NAME;

	class SecureKeyState;
	std::unique_ptr<SecureKeyState> m_secureState;

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
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	explicit SymmetricSecureKey(const std::vector<byte> &Key);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, and nonce parameters.
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, nonce, and info parameters.
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, SecurityPolicy Policy, const std::vector<byte> &Salt);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, and nonce parameters.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, SecurityPolicy Policy, const std::vector<byte> &Salt);

	/// <summary>
	/// Constructor: instantiate this class with an encryption key, nonce, and info parameters.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info, SecurityPolicy Policy, const std::vector<byte> &Salt);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key.
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	explicit SymmetricSecureKey(const SecureVector<byte> &Key);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key, and nonce parameters.
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key, nonce, and info parameters.
	/// <para>This default constructor uses only system specific values to generate the internal ciphers encryption key.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or counter array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const SecureVector<byte> &Key, SecurityPolicy Policy, const SecureVector<byte> &Salt);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key, and nonce parameters.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, SecurityPolicy Policy, const SecureVector<byte> &Salt);

	/// <summary>
	/// Constructor: instantiate this class with a SecureVector encryption key, nonce, and info parameters.
	/// <para>The salt value is added to system and process information to create seed material used by the internal cipher-key generator.</para>
	/// </summary>
	///
	/// <param name="Key">The primary encryption key</param>
	/// <param name="Nonce">The nonce or salt array</param>
	/// <param name="Info">The personalization string or additional keying material</param>
	/// <param name="Policy">The security policy; determines the level of cryptographic security used internally</param>
	/// <param name="Salt">The secret salt array used as an in internal encryption key; the size of the salt should correspond to the SecurityPolicys cryptographic strength</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if an input array size is zero length</exception>
	SymmetricSecureKey(const SecureVector<byte> &Key, const SecureVector<byte> &Nonce, const SecureVector<byte> &Info, SecurityPolicy Policy, const SecureVector<byte> &Salt);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricSecureKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Return a standard-vector copy of the personalization string; can also used as an additional source of entropy in some constructions
	/// </summary>
	/// 
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const std::vector<byte> Info() override;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the primary key
	/// </summary>
	/// 
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const std::vector<byte> Key() override;

	/// <summary>
	/// Read Only: The SymmetricKeySize containing the byte sizes of the key, nonce, and info state members
	/// </summary>
	const SymmetricKeySize KeySizes() override;

	/// <summary>
	/// Read Only: Return a standard-vector copy of the nonce; can also be used as the salt or iv
	/// </summary>
	/// 
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const std::vector<byte> Nonce() override;

	/// <summary>
	/// Create a secure-vector copy of the personalization string; can also used as an additional source of entropy in some constructions
	/// </summary>
	/// 
	/// <exception cref="CryptoSymmetricException">Throws if the output vector is too small</exception>
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const void SecureInfo(SecureVector<byte> &Output);

	/// <summary>
	/// Create a secure-vector copy of the primary encryption key
	/// </summary>
	/// 
	/// <exception cref="CryptoSymmetricException">Throws if the output vector is too small</exception>
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const void SecureKey(SecureVector<byte> &Output);

	/// <summary>
	/// Create a secure-vector copy of the nonce; can also be used as the salt or iv
	/// </summary>
	/// 
	/// <exception cref="CryptoSymmetricException">Throws if the output vector is too small</exception>
	/// <exception cref="CryptoAuthenticationFailure">Throws an authentication failure exception if the internal decryption has failed</exception>
	const void SecureNonce(SecureVector<byte> &Output);

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a copy of this SymmetricSecureKey class
	/// </summary>
	SymmetricSecureKey* Clone();

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
	/// <returns>A pointer to a SymmetricSecureKey container</returns>
	static SymmetricKey* DeSerialize(SecureVector<byte> &KeyStream);

	/// <summary>
	/// Convert a SymmetricSecureKey to a SymmetricKey and serialize it as a SymmetricKey key-stream
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricSecureKey container</param>
	/// 
	/// <returns>A secure-vector containing the serialized SymmetricKey data</returns>
	static SecureVector<byte> Serialize(SymmetricSecureKey &KeyParams);

private:

	static void Encipher(std::unique_ptr<SecureKeyState> &State);
	static void Extract(std::unique_ptr<SecureKeyState> &State, size_t StateOffset, SecureVector<byte> &Output, size_t Length);
	static IStreamCipher* GetStreamCipher(SecurityPolicy Policy);
	static void GetSystemKey(SecurityPolicy Policy, const SecureVector<byte> &Salt, SecureVector<byte> &Output);
};

NAMESPACE_CIPHEREND
#endif
