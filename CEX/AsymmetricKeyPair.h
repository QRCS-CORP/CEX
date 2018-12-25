#ifndef CEX_ASYMMTERICKEYPAIR_H
#define CEX_ASYMMTERICKEYPAIR_H

#include "CexDomain.h"
#include "AsymmetricKey.h"

NAMESPACE_ASYMMETRICKEY

using Key::Asymmetric::AsymmetricKey;

/// <summary>
/// A RingLWE public and private key container
/// </summary>
class AsymmetricKeyPair final
{
private:

	AsymmetricKey* m_privateKey;
	AsymmetricKey* m_publicKey;
	std::vector<byte> m_Tag;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricKeyPair(const AsymmetricKeyPair&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricKeyPair& operator=(const AsymmetricKeyPair&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	AsymmetricKeyPair() = delete;

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key</param>
	/// <param name="PublicKey">The public key</param>
	/// <param name="Tag">The identification tag</param>
	AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. Call the Destroy() function on Public/Private key members,
	/// or let them go out of scope to finalize them.</para>
	/// </summary>
	~AsymmetricKeyPair();

	//~~~Accessors~~~//

	/// <summary>
	/// The secret private Key
	/// </summary>
	AsymmetricKey* PrivateKey();

	/// <summary>
	/// The public key
	/// </summary>
	AsymmetricKey* PublicKey();

	/// <summary>
	/// Read/Write: An optional identification tag
	/// </summary>
	std::vector<byte> &Tag();

private:

	void Destroy();
};

NAMESPACE_ASYMMETRICKEYEND
#endif

