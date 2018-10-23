#ifndef CEX_SPHINCSPUUBLICKEY_H
#define CEX_SPHINCSPUUBLICKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "SphincsParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::SphincsParams;

/// <summary>
/// A Sphincs Public Key container
/// </summary>
class SphincsPublicKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_pCoeffs;
	SphincsParams m_sphincsParameters;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SphincsPublicKey(const SphincsPublicKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SphincsPublicKey& operator=(const SphincsPublicKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SphincsPublicKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="P">The public keys polynomial</param>
	SphincsPublicKey(SphincsParams Parameters, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	explicit SphincsPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SphincsPublicKey() override;

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
	const SphincsParams Parameters();

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
