#ifndef CEX_MPKCPRIVATEKEY_H
#define CEX_MPKCPRIVATEKEY_H

#include "CexDomain.h"
#include "IAsymmetricKey.h"
#include "MPKCParameters.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::MPKCParameters;

/// <summary>
/// A McEliece Private Key container
/// </summary>
class MPKCPrivateKey final : public IAsymmetricKey
{
private:

	bool m_isDestroyed;
	MPKCParameters m_mpkcParameters;
	std::vector<byte> m_sCoeffs;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCPrivateKey(const MPKCPrivateKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MPKCPrivateKey& operator=(const MPKCPrivateKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	MPKCPrivateKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="S">The private key polynomial</param>
	explicit MPKCPrivateKey(MPKCParameters Parameters, std::vector<byte> &S);

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit MPKCPrivateKey(const std::vector<byte> &KeyStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~MPKCPrivateKey() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override;

	/// <summary>
	/// Read Only: The keys type-name
	/// </summary>
	const AsymmetricKeyTypes KeyType() override;

	/// <summary>
	/// Read Only: The cipher parameters enumeration name
	/// </summary>
	const MPKCParameters Parameters();

	/// <summary>
	/// Read Only: The private key polynomial
	/// </summary>
	const std::vector<byte> &S();

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
