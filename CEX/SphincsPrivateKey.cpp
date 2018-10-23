#include "SphincsPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

SphincsPrivateKey::SphincsPrivateKey(SphincsParams Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_sphincsParameters(Parameters),
	m_rCoeffs(R)
{
}

SphincsPrivateKey::SphincsPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_sphincsParameters(SphincsParams::None),
	m_rCoeffs(0)
{
	m_sphincsParameters = static_cast<SphincsParams>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
	{
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
	}
}

SphincsPrivateKey::~SphincsPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines SphincsPrivateKey::CipherType()
{
	return AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes SphincsPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const SphincsParams SphincsPrivateKey::Parameters()
{
	return m_sphincsParameters;
}

const std::vector<byte> &SphincsPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void SphincsPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_sphincsParameters = SphincsParams::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> SphincsPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_sphincsParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
	{
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));
	}

	return r;
}

NAMESPACE_ASYMMETRICKEYEND
