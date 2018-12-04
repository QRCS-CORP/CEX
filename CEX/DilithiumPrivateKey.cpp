#include "DilithiumPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

DilithiumPrivateKey::DilithiumPrivateKey(DilithiumParameters Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_dilithiumParameters(Parameters),
	m_rCoeffs(R)
{
}

DilithiumPrivateKey::DilithiumPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_dilithiumParameters(DilithiumParameters::None),
	m_rCoeffs(0)
{
	m_dilithiumParameters = static_cast<DilithiumParameters>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
	{
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
	}
}

DilithiumPrivateKey::~DilithiumPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines DilithiumPrivateKey::CipherType()
{
	return AsymmetricEngines::Dilithium;
}

const AsymmetricKeyTypes DilithiumPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const DilithiumParameters DilithiumPrivateKey::Parameters()
{
	return m_dilithiumParameters;
}

const std::vector<byte> &DilithiumPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void DilithiumPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dilithiumParameters = DilithiumParameters::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> DilithiumPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_dilithiumParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
	{
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));
	}

	return r;
}

NAMESPACE_ASYMMETRICKEYEND
