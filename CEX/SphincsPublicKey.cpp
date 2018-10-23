#include "SphincsPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

SphincsPublicKey::SphincsPublicKey(SphincsParams Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_sphincsParameters(Parameters),
	m_pCoeffs(P)
{
}

SphincsPublicKey::SphincsPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_sphincsParameters(SphincsParams::None),
	m_pCoeffs(0)
{
	m_sphincsParameters = static_cast<SphincsParams>(KeyStream[0]);
	uint pLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_pCoeffs, 0, pLen);
}

SphincsPublicKey::~SphincsPublicKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines SphincsPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes SphincsPublicKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPublicKey;
}

const SphincsParams SphincsPublicKey::Parameters()
{
	return m_sphincsParameters;
}

const std::vector<byte> &SphincsPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Public Functions~~~//

void SphincsPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_sphincsParameters = SphincsParams::None;

		if (m_pCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_pCoeffs);
		}
	}
}

std::vector<byte> SphincsPublicKey::ToBytes()
{
	uint pLen = static_cast<uint>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 5);

	p[0] = static_cast<byte>(m_sphincsParameters);
	Utility::IntUtils::Le32ToBytes(pLen, p, 1);
	Utility::MemUtils::Copy(m_pCoeffs, 0, p, 5, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND
