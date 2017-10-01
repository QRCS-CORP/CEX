#include "RLWEPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Properties~~~//

const AsymmetricEngines RLWEPrivateKey::CipherType()
{
	return AsymmetricEngines::RingLWE;
}

const RLWEParams RLWEPrivateKey::Parameters()
{
	return m_rlweParameters;
}

const std::vector<ushort> &RLWEPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Constructor~~~//

RLWEPrivateKey::RLWEPrivateKey(RLWEParams Parameters, std::vector<ushort> &R)
	:
	m_isDestroyed(false),
	m_rlweParameters(Parameters),
	m_rCoeffs(R)
{
}

RLWEPrivateKey::RLWEPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_rlweParameters(RLWEParams::None),
	m_rCoeffs(0)
{
	m_rlweParameters = static_cast<RLWEParams>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
}

RLWEPrivateKey::~RLWEPrivateKey()
{
	Destroy();
}

//~~~Public Functions~~~//

void RLWEPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_rlweParameters = RLWEParams::None;

		if (m_rCoeffs.size() > 0)
			Utility::IntUtils::ClearVector(m_rCoeffs);
	}
}

std::vector<byte> RLWEPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_rlweParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));

	return r;
}

NAMESPACE_ASYMMETRICKEYEND