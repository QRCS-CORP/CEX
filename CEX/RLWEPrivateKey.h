#ifndef CEX_RLWEPRIVATEKEY_H
#define CEX_RLWEPRIVATEKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "RLWEParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::RLWEParams;

/// <summary>
/// A RingLWE Private Key container
/// </summary>
class RLWEPrivateKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	std::vector<ushort> m_rCoeffs;
	RLWEParams m_rlweParameters;

public:

	RLWEPrivateKey() = delete;
	RLWEPrivateKey(const RLWEPrivateKey&) = delete;
	RLWEPrivateKey& operator=(const RLWEPrivateKey&) = delete;
	RLWEPrivateKey& operator=(RLWEPrivateKey&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Get: The cipher parameters enumeration name
	/// </summary>
	const RLWEParams Parameters();

	/// <summary>
	/// Get: the private key polynomial R
	/// </summary>
	const std::vector<ushort> &R();

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="R">The private key polynomial</param>
	explicit RLWEPrivateKey(RLWEParams Parameters, std::vector<ushort> &R);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit RLWEPrivateKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~RLWEPrivateKey() override;

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Serialize a private key to a byte array
	/// </summary>
	std::vector<byte> ToBytes() override;
};

NAMESPACE_ASYMMETRICKEYEND
#endif
