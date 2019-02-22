#ifndef CEX_ASYMMETRICSECUREKEY_H
#define CEX_ASYMMETRICSECUREKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "AsymmetricPrimitives.h"
#include "AsymmetricKey.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricTransforms.h"
#include "IStreamCipher.h"
#include "SecurityPolicy.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricPrimitives;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricTransforms;
using Cipher::Stream::IStreamCipher;
using Enumeration::SecurityPolicy;

/// <summary>
/// An encrypted and authenticated Asymmetric primitive key container.
/// <para>Contains the keys polynomial vector, the key classification, primitive type, and the primitives parameter-set type name.
/// Internal polynomial storage uses a secure-vector encrypted with an optionally authenticated threefish cipher instance. \n
/// The authentication option, and the ciphers strength (256/512/1024), are set through the SecurityPolicy enumeration in the class constructors. \n
/// The cipher key is derived from system information and various process handles along with a salt value, this is processed by an instance of cSHAKE to produce the cipher key. \n
/// The vector containing the asymmetric primitives key polynomial, can be accessed through a secure-vector copy using SecurePolynomial, or return a standard-vector copy with the Polynomial accessor.<para>
/// </summary>
class AsymmetricSecureKey final : public IAsymmetricKey
{
private:

	static const std::string CLASS_NAME;

	class AsymmetricSecureKeyState;
	std::unique_ptr<AsymmetricSecureKeyState> m_secureState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricSecureKey(const AsymmetricSecureKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricSecureKey& operator=(const AsymmetricSecureKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	AsymmetricSecureKey() = delete;

	/// <summary>
	/// Initialize this class with an asymmetric standard-vector polynomial and the asymmetric primitives parameter settings
	/// </summary>
	/// 
	/// <param name="Polynomial">The asymmetric keys polynomial standard-vector</param>
	/// <param name="PrimitiveType">The asymmetric primitive enumeration</param>
	/// <param name="KeyClass">The asymmetric primitives key classification enumeration</param>
	/// <param name="Parameters">The asymmetric primitives parameter-set enumeration</param>
	/// <param name="KeySalt">The optional secret salt vector used in internal encryption</param>
	/// <param name="PolicyType">The asymmetric keys security policy</param>
	///
	/// <exception cref="CryptoAsymmetricException">Thrown if invalid parameters or an empty polynomial vector are passed</exception>
	AsymmetricSecureKey(const std::vector<byte> &Polynomial, const std::vector<byte> &KeySalt, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricTransforms Parameters, SecurityPolicy PolicyType);

	/// <summary>
	/// Initialize this class with an asymmetric secure-vector polynomial and the asymmetric primitives parameter settings
	/// </summary>
	/// 
	/// <param name="Polynomial">The asymmetric keys polynomial secure-vector</param>
	/// <param name="PrimitiveType">The asymmetric primitive enumeration</param>
	/// <param name="KeyClass">The asymmetric primitives key classification enumeration</param>
	/// <param name="Parameters">The asymmetric primitives parameter-set enumeration</param>
	/// <param name="KeySalt">The optional secret salt vector used in internal encryption</param>
	/// <param name="PolicyType">The asymmetric keys security policy</param>
	///
	/// <exception cref="CryptoAsymmetricException">Thrown if invalid parameters or an empty polynomial vector are passed</exception>
	AsymmetricSecureKey(const SecureVector<byte> &Polynomial, const SecureVector<byte> &KeySalt, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricTransforms Parameters, SecurityPolicy PolicyType);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AsymmetricSecureKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The keys classification type enumeration
	/// </summary>
	const AsymmetricKeyTypes KeyClass() override;

	/// <summary>
	/// Read Only: The asymmetric primitives parameter-set enumeration
	/// </summary>
	const AsymmetricTransforms Parameters() override;

	/// <summary>
	/// ead Only: The keys asymmetric primitive enumeration type
	/// </summary>
	const AsymmetricPrimitives PrimitiveType() override;

	/// <summary>
	/// Read Only: The asymmetric keys standard-vector polynomial
	/// </summary>
	const std::vector<byte> Polynomial() override;

	/// <summary>
	/// Read Only: The asymmetric keys secure-vector polynomial
	/// </summary>
	const void SecurePolynomial(SecureVector<byte> &Output);

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Reset() override;

	//~~~Static Functions~~~//

	/// <summary>
	/// Deserialize an AsymmetricKey key-stream and return a pointer to an AsymmetricKey
	/// </summary>
	/// 
	/// <param name="KeyStream">Stream containing the serialized AsymmetricKey</param>
	/// 
	/// <returns>A populated AsymmetricKey container</returns>
	static AsymmetricKey* DeSerialize(SecureVector<byte> &KeyStream);

	/// <summary>
	/// Serialize and convert an AsymmetricSecureKey into an AsymmetricKey key-stream
	/// </summary>
	/// 
	/// <param name="KeyParams">The AsymmetricKey key container</param>
	/// 
	/// <returns>A key-stream containing a serialized AsymmetricKey key</returns>
	static SecureVector<byte> Serialize(AsymmetricSecureKey &KeyParams);

	//~~~Private Functions~~~//

	static void Encipher(std::unique_ptr<AsymmetricSecureKeyState> &State);
	static void Extract(std::unique_ptr<AsymmetricSecureKeyState> &State, SecureVector<byte> &Output, size_t Length);
	static IStreamCipher* GetStreamCipher(SecurityPolicy Policy);
	static void GetSystemKey(SecurityPolicy Policy, const SecureVector<byte> &Salt, SecureVector<byte> &Output);
};

NAMESPACE_ASYMMETRICEND
#endif
