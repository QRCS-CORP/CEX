#ifndef CEX_ASYMMETRICKEY_H
#define CEX_ASYMMETRICKEY_H

#include "CexDomain.h"
#include "AsymmetricKeyTypes.h"
#include "AsymmetricTransforms.h"
#include "IAsymmetricKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

using Enumeration::AsymmetricTransforms;
using Utility::IntUtils;

/// <summary>
/// An Asymmetric cipher key container
/// </summary>
class AsymmetricKey final : public IAsymmetricKey
{
private:

	AsymmetricEngines m_cipherEngine;
	AsymmetricKeyTypes m_cipherKey;
	AsymmetricTransforms m_cipherParams;
	bool m_isDestroyed;
	std::vector<byte> m_polyCoeffs;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricKey(const AsymmetricKey&) = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AsymmetricKey& operator=(const AsymmetricKey&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	AsymmetricKey() = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The asymmetric cipher algorithm enumeration name</param>
	/// <param name="CipherKeyType">The asymmetric cipher key type enumeration name</param>
	/// <param name="ParameterType">The asymmetric cipher parameter-set enumeration name</param>
	/// <param name="P">The cipher key polynomial array</param>
	///
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if invalid parameters are used</exception>
	AsymmetricKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P)
		:
		m_cipherEngine(CipherType != AsymmetricEngines::None ? CipherType : 
			throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher engine type can not be None!")),
		m_cipherKey(CipherKeyType != AsymmetricKeyTypes::None ? CipherKeyType : 
			throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher key type can not be None!")),
		m_cipherParams(ParameterType != AsymmetricTransforms::None ? ParameterType : 
			throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher parameters type can not be None!")),
		m_isDestroyed(false),
		m_polyCoeffs(P.size() != 0 ? P : 
			throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The polynomial array can not be zero length!"))
	{
	}

	/// <summary>
	/// Initialize this class with a serialized private key
	/// </summary>
	/// 
	/// <param name="KeyStream">The serialized private key</param>
	explicit AsymmetricKey(const std::vector<byte> &KeyStream)
		:
		m_isDestroyed(false)
	{
		m_cipherEngine = static_cast<AsymmetricEngines>(KeyStream[0]);
		m_cipherKey = static_cast<AsymmetricKeyTypes>(KeyStream[1]);
		m_cipherParams = static_cast<AsymmetricTransforms>(KeyStream[2]);
		uint plen = Utility::IntUtils::LeBytesTo32(KeyStream, 3);
		m_polyCoeffs.resize(plen);
		Utility::MemUtils::Copy(KeyStream, 7, m_polyCoeffs, 0, plen);
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AsymmetricKey() override
	{
		Destroy();
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The private keys cipher type name
	/// </summary>
	const AsymmetricEngines CipherType() override
	{
		return m_cipherEngine;
	}

	/// <summary>
	/// Read Only: The keys type-name
	/// </summary>
	const AsymmetricKeyTypes KeyType() override
	{
		return m_cipherKey;
	}

	/// <summary>
	/// Read Only: The cipher parameters enumeration name
	/// </summary>
	const AsymmetricTransforms Parameters()
	{
		return m_cipherParams;
	}

	/// <summary>
	/// Read Only: The private key polynomial
	/// </summary>
	const std::vector<byte> &P()
	{
		return m_polyCoeffs;
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override
	{
		if (!m_isDestroyed)
		{
			m_isDestroyed = true;
			m_cipherEngine = AsymmetricEngines::None;
			m_cipherKey = AsymmetricKeyTypes::None;
			m_cipherParams = AsymmetricTransforms::None;

			if (m_polyCoeffs.size() > 0)
			{
				Utility::IntUtils::ClearVector(m_polyCoeffs);
			}
		}
	}

	/// <summary>
	/// Serialize a private key to a byte array
	/// </summary>
	std::vector<byte> ToBytes() override
	{
		uint plen = static_cast<uint>(m_polyCoeffs.size());
		std::vector<byte> poly(plen + 7);
		poly[0] = static_cast<byte>(m_cipherEngine);
		poly[1] = static_cast<byte>(m_cipherKey);
		poly[2] = static_cast<byte>(m_cipherParams);
		Utility::IntUtils::Le32ToBytes(plen, poly, 3);
		Utility::MemUtils::Copy(poly, 7, m_polyCoeffs, 0, plen);

		return poly;
	}
};

NAMESPACE_ASYMMETRICKEYEND
#endif
