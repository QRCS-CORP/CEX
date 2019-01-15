#ifndef CEX_ASYMMETRICSECUREKEY_H
#define CEX_ASYMMETRICSECUREKEY_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricTransforms.h"
#include "IAsymmetricKey.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricEngines;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricTransforms;

/// <summary>
/// An Asymmetric cipher key container
/// </summary>
class AsymmetricSecureKey final : public IAsymmetricKey
{
private:

	AsymmetricEngines m_cipherEngine;
	AsymmetricKeyTypes m_cipherKey;
	AsymmetricTransforms m_cipherParams;
	bool m_isDestroyed;
	std::vector<byte> m_polyCoeffs;

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
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The asymmetric cipher algorithm enumeration name</param>
	/// <param name="CipherKeyType">The asymmetric cipher key type enumeration name</param>
	/// <param name="ParameterType">The asymmetric cipher parameter-set enumeration name</param>
	/// <param name="P">The cipher key polynomial array</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	///
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if invalid parameters are used</exception>
	AsymmetricSecureKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P, ulong KeySalt = 0);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit AsymmetricSecureKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AsymmetricSecureKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Read Only: The keys type-name
	/// </summary>
	const AsymmetricKeyTypes KeyType() override;

	/// <summary>
	/// Read Only: The cipher parameters enumeration name
	/// </summary>
	const AsymmetricTransforms Parameters() override;

	/// <summary>
	/// Read Only: The private key polynomial
	/// </summary>
	const std::vector<byte> &P() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Serialize a private key to a byte array
	/// </summary>
	std::vector<byte> ToBytes() override;
};

NAMESPACE_ASYMMETRICEND
#endif
