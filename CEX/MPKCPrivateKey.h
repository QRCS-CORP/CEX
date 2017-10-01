#ifndef CEX_MPKCPRIVATEKEY_H
#define CEX_MPKCPRIVATEKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "MPKCParams.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::MPKCParams;

/// <summary>
/// A McEliece Private Key container
/// </summary>
class MPKCPrivateKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	MPKCParams m_mpkcParameters;
	std::vector<byte> m_sCoeffs;

public:

	MPKCPrivateKey() = delete;
	MPKCPrivateKey(const MPKCPrivateKey&) = delete;
	MPKCPrivateKey& operator=(const MPKCPrivateKey&) = delete;
	MPKCPrivateKey& operator=(MPKCPrivateKey&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Get: The cipher parameters enumeration name
	/// </summary>
	const MPKCParams Parameters();

	/// <summary>
	/// Get: The private key polynomial
	/// </summary>
	const std::vector<byte> &S() { return m_sCoeffs; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="S">The private key polynomial</param>
	explicit MPKCPrivateKey(MPKCParams Params, std::vector<byte> &S);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit MPKCPrivateKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MPKCPrivateKey() override;

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
