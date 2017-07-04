#ifndef _CEX_MPKCPUUBLICKEY_H
#define _CEX_MPKCPUUBLICKEY_H

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
	std::vector<byte> m_pCoeffs;
	MPKCParams m_mpkcParameters;

public:

	MPKCPublicKey() = delete;
	MPKCPublicKey(const MPKCPublicKey&) = delete;
	MPKCPublicKey& operator=(const MPKCPublicKey&) = delete;
	MPKCPublicKey& operator=(MPKCPublicKey&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The public keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Get: The cipher parameters enumeration name
	/// </summary>
	const MPKCParams Parameters();

	/// <summary>
	/// Get: The public keys polynomial
	/// </summary>
	const std::vector<byte> &P();

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="P">The The public keys polynomial</param>
	MPKCPublicKey(MPKCParams Parameters, std::vector<byte> &P);

	/// <summary>
	/// Initialize this class with a serialized public key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized public key</param>
	MPKCPublicKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MPKCPublicKey() override;

	//~~~Public Methods~~~//

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
