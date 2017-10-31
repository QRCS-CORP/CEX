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

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RLWEPrivateKey(const RLWEPrivateKey&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RLWEPrivateKey& operator=(const RLWEPrivateKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	RLWEPrivateKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="R">The private key polynomial</param>
	RLWEPrivateKey(RLWEParams Parameters, std::vector<ushort> &R);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit RLWEPrivateKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~RLWEPrivateKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Read Only: The cipher parameters enumeration name
	/// </summary>
	const RLWEParams Parameters();

	/// <summary>
	/// Read Only: the private key polynomial R
	/// </summary>
	const std::vector<ushort> &R();

	//~~~Public Functions~~~//

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
