#ifndef CEX_IASYMMETRICKEYPAIR_H
#define CEX_IASYMMETRICKEYPAIR_H

#include "CexDomain.h"
#include "CryptoAsymmetricException.h"
#include "IAsymmetricKey.h"

NAMESPACE_ASYMMETRICKEY

using Exception::CryptoAsymmetricException;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKeyPair
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKeyPair(const IAsymmetricKeyPair&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAsymmetricKeyPair& operator=(const IAsymmetricKeyPair&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IAsymmetricKeyPair() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	virtual ~IAsymmetricKeyPair() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// The public key
	/// </summary>
	virtual IAsymmetricKey* PublicKey() = 0;

	/// <summary>
	/// The secret private Key
	/// </summary>
	virtual IAsymmetricKey* PrivateKey() = 0;

	/// <summary>
	/// Read Only: An optional unique tag identifying this key-pair
	/// </summary>
	virtual const std::vector<byte> &Tag() = 0;
};

NAMESPACE_ASYMMETRICKEYEND
#endif

