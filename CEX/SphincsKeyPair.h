#ifndef CEX_SPHINCSKEYPAIR_H
#define CEX_SPHINCSKEYPAIR_H

#include "CexDomain.h"
#include "IAsymmetricKeyPair.h"
#include "SphincsPrivateKey.h"
#include "SphincsPublicKey.h"

NAMESPACE_ASYMMETRICKEY

/// <summary>
/// A Sphincs+ public and private key container
/// </summary>
class SphincsKeyPair final : public IAsymmetricKeyPair
{
private:

	SphincsPrivateKey* m_privateKey;
	SphincsPublicKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SphincsKeyPair(const SphincsKeyPair&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SphincsKeyPair& operator=(const SphincsKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SphincsKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	SphincsKeyPair(SphincsPrivateKey* PrivateKey, SphincsPublicKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	SphincsKeyPair(SphincsPrivateKey* PrivateKey, SphincsPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~SphincsKeyPair() override;

	//~~~Accessors~~~//

	/// <summary>
	/// The secret private Key
	/// </summary>
	IAsymmetricKey* PrivateKey() override;

	/// <summary>
	/// The public key
	/// </summary>
	IAsymmetricKey* PublicKey() override;

	/// <summary>
	/// Read/Write: An optional identification tag
	/// </summary>
	std::vector<byte> &Tag() override;

private:

	void Destroy();
};

NAMESPACE_ASYMMETRICKEYEND
#endif

