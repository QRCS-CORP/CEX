#include "RLWEPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_KEYASYMMETRIC

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
	m_rlweParameters = static_cast<RLWEParams>(Utility::IntUtils::LeBytesTo16(KeyStream, 0));
	uint rLen = Utility::IntUtils::LeBytesTo16(KeyStream, 2);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 4 + (i * sizeof(ushort)));
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
		m_rlweParameters = RLWEParams::None;

		if (m_rCoeffs.size() > 0)
			Utility::IntUtils::ClearVector(m_rCoeffs);

		m_isDestroyed = true;
	}
}

std::vector<byte> RLWEPrivateKey::ToBytes()
{
	ushort rLen = static_cast<ushort>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 4);
	Utility::IntUtils::Le16ToBytes(static_cast<ushort>(m_rlweParameters), r, 0);
	Utility::IntUtils::Le16ToBytes(rLen, r, 2);

	for (size_t i = 0; i < rLen; ++i)
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 4 + (i * sizeof(ushort)));

	return r;
}

NAMESPACE_KEYASYMMETRICEND