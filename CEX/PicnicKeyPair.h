#ifndef CEX_PICNICKEYPAIR_H
#define CEX_PICNICKEYPAIR_H

#include "CexDomain.h"
#include "IAsymmetricKeyPair.h"
#include "PicnicPrivateKey.h"
#include "PicnicPublicKey.h"

NAMESPACE_ASYMMETRICKEY

/// <summary>
/// A Dilithium+ public and private key container
/// </summary>
class PicnicKeyPair final : public IAsymmetricKeyPair
{
private:

	PicnicPrivateKey* m_privateKey;
	PicnicPublicKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	PicnicKeyPair(const PicnicKeyPair&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	PicnicKeyPair& operator=(const PicnicKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	PicnicKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	PicnicKeyPair(PicnicPrivateKey* PrivateKey, PicnicPublicKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	PicnicKeyPair(PicnicPrivateKey* PrivateKey, PicnicPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~PicnicKeyPair() override;

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

