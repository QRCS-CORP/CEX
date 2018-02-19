#ifndef CEX_RLWEPUUBLICKEY_H
#define CEX_RLWEPUUBLICKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "RLWEParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::RLWEParams;

/// <summary>
/// A RingLWE Public Key container
/// </summary>
class RLWEPublicKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_pCoeffs;
	RLWEParams m_rlweParameters;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RLWEPublicKey(const RLWEPublicKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RLWEPublicKey& operator=(const RLWEPublicKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	RLWEPublicKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="P">The public keys polynomial</param>
	RLWEPublicKey(RLWEParams Parameters, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	explicit RLWEPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~RLWEPublicKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The public keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Read Only: The keys type-name
	/// </summary>
	const AsymmetricKeyTypes KeyType() override;

	/// <summary>
	/// Read Only: The cipher parameters enumeration name
	/// </summary>
	const RLWEParams Parameters();

	/// <summary>
	/// Read Only: The public keys polynomial
	/// </summary>
	const std::vector<byte> &P();

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Serialize a public key to a byte array
	/// </summary>
	std::vector<byte> ToBytes() override;
};

NAMESPACE_ASYMMETRICKEYEND
#endif
