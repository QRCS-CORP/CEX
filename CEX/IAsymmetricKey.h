#ifndef CEX_IASYMMETRICKEY_H
#define CEX_IASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::AsymmetricEngines;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKey
{
public:

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The keys parent cipher type-name
	/// </summary>
	virtual const AsymmetricEngines CipherType() = 0;

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

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Serialize the key
	/// </summary>
	virtual std::vector<byte> ToBytes() = 0;
};

NAMESPACE_ASYMMETRICKEYEND
#endif

