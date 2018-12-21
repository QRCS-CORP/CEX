#ifndef CEX_IASYMMETRICKEY_H
#define CEX_IASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricEngines.h"
#include "AsymmetricKeyTypes.h"
#include "CryptoAsymmetricException.h"
#include "MemoryStream.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::AsymmetricEngines;
using Enumeration::AsymmetricKeyTypes;
using Exception::CryptoAsymmetricException;
using IO::MemoryStream;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKey
{
public:

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The keys parent cipher type-name AsymmetricKeyTypes
	/// </summary>
	virtual const AsymmetricEngines CipherType() = 0;

	/// <summary>
	/// Read Only: The keys type-name
	/// </summary>
	virtual const AsymmetricKeyTypes KeyType() = 0;

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

