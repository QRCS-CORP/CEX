#ifndef _CEX_IASYMMETRICKEYPAIR_H
#define _CEX_IASYMMETRICKEYPAIR_H

#include "CexDomain.h"
#include "CryptoAsymmetricException.h"
#include "IAsymmetricKey.h"

NAMESPACE_KEYASYMMETRIC

using Exception::CryptoAsymmetricException;

/// <summary>
/// The Asymmetric key interface
/// </summary>
class IAsymmetricKeyPair
{
public:

	IAsymmetricKeyPair(const IAsymmetricKeyPair&) = delete;
	IAsymmetricKeyPair& operator=(const IAsymmetricKeyPair&) = delete;

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
	/// Get: An optional unique tag identifying this key-pair
	/// </summary>
	virtual const std::vector<byte> Tag() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// The Public key
	/// </summary>
	virtual const IAsymmetricKey &PublicKey() = 0;

	/// <summary>
	/// The Private Key
	/// </summary>
	virtual const IAsymmetricKey &PrivateKey() = 0;
};

NAMESPACE_KEYASYMMETRICEND
#endif

