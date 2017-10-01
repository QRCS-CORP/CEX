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

	//~~~Properties~~~//

	/// <summary>
	/// Get: The keys parent cipher type-name
	/// </summary>
	virtual const AsymmetricEngines CipherType() = 0;

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IAsymmetricKey() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IAsymmetricKey() {}

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

