#ifndef CEX_ASYMMTERICKEYPAIR_H
#define CEX_ASYMMTERICKEYPAIR_H

#include "CexDomain.h"
#include "AsymmetricKey.h"

NAMESPACE_ASYMMETRIC

/// <summary>
/// An asymmetric key-pair container.
/// <para>Contains private and public asymmetric keys, and an optional key-pair identification tag.</para>
/// </summary>
class AsymmetricKeyPair final
{
private:

	AsymmetricKey* m_privateKey;
	AsymmetricKey* m_publicKey;
	std::vector<byte> m_keyTag;

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
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="PublicKey">The public asymmetric key</param>
	AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey);

	/// <summary>
	/// Constructor: instantiate this class with the public/private keys and an identification tag
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="Tag">The key-pairs identification tag</param>
	AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey, std::vector<byte> &Tag);

	/// <summary>
	/// Destructor: finalize this class.
	/// <para>Only the tag is destroyed in the finalizer. 
	/// Call the Reset() function to clear Public and Private key members,
	/// or let them finalize by going out of scope.</para>
	/// </summary>
	~AsymmetricKeyPair();

	//~~~Accessors~~~//

	/// <summary>
	/// The secret asymmetric private Key
	/// </summary>
	AsymmetricKey* PrivateKey();

	/// <summary>
	/// The asymmetric public key
	/// </summary>
	AsymmetricKey* PublicKey();

	/// <summary>
	/// Read/Write: An optional key-pair identification tag
	/// </summary>
	std::vector<byte> &Tag();

	/// <summary>
	/// Clear all internal state, including the key-pair tag and public and private keys
	/// </summary>
	void Reset();
};

NAMESPACE_ASYMMETRICEND
#endif

