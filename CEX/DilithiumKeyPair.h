#ifndef CEX_DILITHIUMKEYPAIR_H
#define CEX_DILITHIUMKEYPAIR_H

#include "CexDomain.h"
#include "DilithiumPrivateKey.h"
#include "DilithiumPublicKey.h"
#include "IAsymmetricKeyPair.h"

NAMESPACE_ASYMMETRICKEY

/// <summary>
/// A Dilithium+ public and private key container
/// </summary>
class DilithiumKeyPair final : public IAsymmetricKeyPair
{
private:

	DilithiumPrivateKey* m_privateKey;
	DilithiumPublicKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	DilithiumKeyPair(const DilithiumKeyPair&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	DilithiumKeyPair& operator=(const DilithiumKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	DilithiumKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	DilithiumKeyPair(DilithiumPrivateKey* PrivateKey, DilithiumPublicKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	DilithiumKeyPair(DilithiumPrivateKey* PrivateKey, DilithiumPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~DilithiumKeyPair() override;

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

