#ifndef CEX_DILITHIUMPUUBLICKEY_H
#define CEX_DILITHIUMPUUBLICKEY_H

#include "CexDomain.h"
#include "DilithiumParameters.h"
#include "IAsymmetricKey.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::DilithiumParameters;

/// <summary>
/// A Dilithium Public Key container
/// </summary>
class DilithiumPublicKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_pCoeffs;
	DilithiumParameters m_dilithiumParameters;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	DilithiumPublicKey(const DilithiumPublicKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	DilithiumPublicKey& operator=(const DilithiumPublicKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	DilithiumPublicKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="P">The public keys polynomial</param>
	DilithiumPublicKey(DilithiumParameters Parameters, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	explicit DilithiumPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~DilithiumPublicKey() override;

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
	const DilithiumParameters Parameters();

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
