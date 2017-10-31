#ifndef CEX_RLWEKEYPAIR_H
#define CEX_RLWEKEYPAIR_H

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

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RLWEKeyPair(const RLWEKeyPair&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RLWEKeyPair& operator=(const RLWEKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	RLWEKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~RLWEKeyPair() override;

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
	/// Read Only: An optional identification tag
	/// </summary>
	const std::vector<byte> &Tag() override;

private:

	void Destroy();
};

NAMESPACE_ASYMMETRICKEYEND
#endif

