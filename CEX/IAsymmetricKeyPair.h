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
	/// CTor: Instantiate this class
	/// </summary>
	IAsymmetricKeyPair() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IAsymmetricKeyPair() {}

	//~~~Properties~~~//

	/// <summary>
	/// The public key
	/// </summary>
	virtual IAsymmetricKey* PublicKey() = 0;

	/// <summary>
	/// The secret private Key
	/// </summary>
	virtual IAsymmetricKey* PrivateKey() = 0;

	/// <summary>
	/// Get: An optional unique tag identifying this key-pair
	/// </summary>
	virtual const std::vector<byte> &Tag() = 0;
};

NAMESPACE_ASYMMETRICKEYEND
#endif

