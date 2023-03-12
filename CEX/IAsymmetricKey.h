#ifndef CEX_IASYMMETRICKEY_H
#define CEX_IASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricPrimitives.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricParameters.h"
#include "CryptoAsymmetricException.h"
#include "SecureVector.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricPrimitives;
using Enumeration::AsymmetricKeyTypes;
using Enumeration::AsymmetricParameters;
using Exception::CryptoAsymmetricException;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKey
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKey(const IAsymmetricKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKey& operator=(const IAsymmetricKey&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricKey() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IAsymmetricKey() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The keys private/public classification type
	/// </summary>
	virtual const AsymmetricKeyTypes KeyClass() = 0;

	/// <summary>
	/// Read Only: The keys asymmetric primitive type-name
	/// </summary>
	virtual const AsymmetricPrimitives PrimitiveType() = 0;

	/// <summary>
	/// Read Only: The asymmetric primitives parameter type-name
	/// </summary>
	virtual const AsymmetricParameters Parameters() = 0;

	/// <summary>
	/// Read Only: Returns a standard-vector copy of the asymmetric-key polynomial
	/// </summary>
	virtual const std::vector<uint8_t> Polynomial() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_ASYMMETRICEND
#endif

