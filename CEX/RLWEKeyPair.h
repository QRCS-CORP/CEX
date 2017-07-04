#ifndef _CEX_RLWEKEYPAIR_H
#define _CEX_RLWEKEYPAIR_H

#include "CexDomain.h"
#include "IAsymmetricKeyPair.h"
#include "RLWEPrivateKey.h"
#include "RLWEPublicKey.h"

NAMESPACE_ASYMMETRICKEY

/// <summary>
/// A RingLWE public and private key container
/// </summary>
class RLWEKeyPair final : public IAsymmetricKeyPair
{
private:

	RLWEPrivateKey* m_privateKey;
	RLWEPublicKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	RLWEKeyPair(const RLWEKeyPair&) = delete;
	RLWEKeyPair& operator=(const RLWEKeyPair&) = delete;
	RLWEKeyPair& operator=(RLWEKeyPair&&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey);

	/// <summary>
	/// Instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~RLWEKeyPair() override;

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

NAMESPACE_ASYMMETRICKEYEND
#endif

