#ifndef CEX_MPKCKEYPAIR_H
#define CEX_MPKCKEYPAIR_H

#include "CexDomain.h"
#include "IAsymmetricKeyPair.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_ASYMMETRICKEY

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

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCKeyPair(const MPKCKeyPair&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCKeyPair& operator=(const MPKCKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	MPKCKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~MPKCKeyPair() override;

	//~~~Accessors~~~//

	/// <summary>
	/// The Private Key
	/// </summary>
	IAsymmetricKey* PrivateKey() override;

	/// <summary>
	/// The Public key
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

