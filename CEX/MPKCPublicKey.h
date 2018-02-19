#ifndef CEX_MPKCPUUBLICKEY_H
#define CEX_MPKCPUUBLICKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "MPKCParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::MPKCParams;

/// <summary>
/// A McEliece Private Key container
/// </summary>
class MPKCPublicKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_pubMat;
	MPKCParams m_mpkcParameters;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCPublicKey(const MPKCPublicKey&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MPKCPublicKey& operator=(const MPKCPublicKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	MPKCPublicKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Params">The cipher parameter enumeration name</param>
	/// <param name="P">The The public keys polynomial</param>
	explicit MPKCPublicKey(MPKCParams Params, const std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	explicit MPKCPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~MPKCPublicKey() override;

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
	const MPKCParams Parameters();

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
