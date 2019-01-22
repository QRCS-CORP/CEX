#ifndef CEX_ASYMMETRICKEY_H
#define CEX_ASYMMETRICKEY_H

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
class AsymmetricKey final : public IAsymmetricKey
{
private:

	static const std::string CLASS_NAME;

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
	AsymmetricKey(const AsymmetricKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricKey& operator=(const AsymmetricKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	AsymmetricKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The asymmetric cipher algorithm enumeration name</param>
	/// <param name="CipherKeyType">The asymmetric cipher key type enumeration name</param>
	/// <param name="ParameterType">The asymmetric cipher parameter-set enumeration name</param>
	/// <param name="P">The cipher key polynomial array</param>
	///
	/// <exception cref="CryptoAsymmetricException">Thrown if invalid parameters are used</exception>
	AsymmetricKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit AsymmetricKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AsymmetricKey() override;

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
