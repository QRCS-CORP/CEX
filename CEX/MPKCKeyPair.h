#ifndef _CEX_MPKCKEYPAIR_H
#define _CEX_MPKCKEYPAIR_H

#include "CexDomain.h"
#include "IAsymmetricKeyPair.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_KEYASYMMETRIC

/// <summary>
/// A McEliece public and private key container
/// </summary>
class MPKCKeyPair final : public IAsymmetricKeyPair
{
private:

	MPKCPrivateKey* m_privateKey;
	MPKCPublicKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	MPKCKeyPair(const MPKCKeyPair&) = delete;
	MPKCKeyPair& operator=(const MPKCKeyPair&) = delete;
	MPKCKeyPair& operator=(MPKCKeyPair&&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey);

	/// <summary>
	/// Instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MPKCKeyPair() override;

	//~~~Properties~~~//

	/// <summary>
	/// The Private Key
	/// </summary>
	IAsymmetricKey* PrivateKey() override;

	/// <summary>
	/// The Public key
	/// </summary>
	IAsymmetricKey* PublicKey() override;

	/// <summary>
	/// An optional identification tag
	/// </summary>
	const std::vector<byte> &Tag() override;

private:

	void Destroy();
};

NAMESPACE_KEYASYMMETRICEND
#endif

