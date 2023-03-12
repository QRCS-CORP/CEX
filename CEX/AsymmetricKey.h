#ifndef CEX_ASYMMETRICKEY_H
#define CEX_ASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricPrimitives.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricParameters.h"
#include "IAsymmetricKey.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricPrimitives;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricParameters;

/// <summary>
/// An Asymmetric primitive key container.
/// <para>Contains the keys polynomial vector, the key classification, primitive type, and the primitives parameter-set type name.
/// Internal storage uses a secure-vector, which can be accessed directly using SecurePolynomial, or return a standard-vector copy with the Polynomial accessor.<para>
/// </summary>
class AsymmetricKey final : public IAsymmetricKey
{
private:

	static const std::string CLASS_NAME;

	class AsymmetricKeyState;
	std::unique_ptr<AsymmetricKeyState> m_keyState;

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
	/// Initialize an AsymmetricKey container
	/// </summary>
	/// 
	/// <param name="Polynomial">The asymmetric primitives polynomial key standard-vector</param>
	/// <param name="PrimitiveType">The keys asymmetric primitives enumeration name</param>
	/// <param name="KeyClass">The asymmetric primitives key classification enumeration name</param>
	/// <param name="ParameterType">The asymmetric primitives parameter-set enumeration name</param>
	///
	/// <exception cref="CryptoAsymmetricException">Thrown if invalid parameters are passed</exception>
	AsymmetricKey(const std::vector<uint8_t> &Polynomial, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters ParameterType);

	/// <summary>
	/// Initialize an AsymmetricKey container
	/// </summary>
	/// 
	/// <param name="Polynomial">The asymmetric primitives polynomial key secure-vector</param>
	/// <param name="PrimitiveType">The keys asymmetric primitives enumeration name</param>
	/// <param name="KeyClass">The asymmetric primitives key classification enumeration name</param>
	/// <param name="ParameterType">The asymmetric primitives parameter-set enumeration name</param>
	///
	/// <exception cref="CryptoAsymmetricException">Thrown if invalid parameters are passed</exception>
	AsymmetricKey(const SecureVector<uint8_t> &Polynomial, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters ParameterType);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AsymmetricKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The keys classification enumeration name
	/// </summary>
	const AsymmetricKeyTypes KeyClass() override;

	/// <summary>
	/// ead Only: The keys asymmetric primitives enumeration name
	/// </summary>
	const AsymmetricPrimitives PrimitiveType() override;

	/// <summary>
	/// Read Only: The asymmetric primitives parameter-set enumeration name
	/// </summary>
	const AsymmetricParameters Parameters() override;

	/// <summary>
	/// Read Only: Returns a copy of the asymmetric keys standard-vector polynomial
	/// </summary>
	const std::vector<uint8_t> Polynomial() override;

	/// <summary>
	/// Read Only: Returns a reference to the internal asymmetric keys secure-vector polynomial
	/// </summary>
	const SecureVector<uint8_t> &SecurePolynomial();

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
	static AsymmetricKey* DeSerialize(SecureVector<uint8_t> &KeyStream);

	/// <summary>
	/// Serialize an AsymmetricKey into a secure-vector key-stream
	/// </summary>
	/// 
	/// <param name="KeyParams">The AsymmetricKey key container</param>
	/// 
	/// <returns>A key-stream containing a serialized AsymmetricKey key</returns>
	static SecureVector<uint8_t> Serialize(AsymmetricKey &KeyParams);
};

NAMESPACE_ASYMMETRICEND
#endif
