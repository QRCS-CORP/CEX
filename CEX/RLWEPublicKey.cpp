#include "RLWEPublicKey.h"
#include "IntUtils.h"

NAMESPACE_KEYASYMMETRIC

//~~~Properties~~~//

const AsymmetricEngines RLWEPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::RingLWE;
}

const RLWEParams RLWEPublicKey::Parameters()
{
	return m_rlweParameters;
}

const std::vector<byte> &RLWEPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Constructor~~~//

RLWEPublicKey::RLWEPublicKey(RLWEParams Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_rlweParameters(Parameters),
	m_pCoeffs(P)
{
}

RLWEPublicKey::RLWEPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_rlweParameters(RLWEParams::None),
	m_pCoeffs(0)
{
	m_rlweParameters = static_cast<RLWEParams>(Utility::IntUtils::LeBytesTo16(KeyStream, 0));
	uint pLen = Utility::IntUtils::LeBytesTo16(KeyStream, 2);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy<byte, byte>(KeyStream, 4, m_pCoeffs, 0, pLen);
}

RLWEPublicKey::~RLWEPublicKey()
{
	Destroy();
}

//~~~Public Functions~~~//

void RLWEPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_rlweParameters = RLWEParams::None;

		if (m_pCoeffs.size() > 0)
			Utility::IntUtils::ClearVector(m_pCoeffs);

		m_isDestroyed = true;
	}
}

std::vector<byte> RLWEPublicKey::ToBytes()
{
	ushort pLen = static_cast<ushort>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 4);
	Utility::IntUtils::Le16ToBytes(static_cast<ushort>(m_rlweParameters), p, 0);
	Utility::IntUtils::Le16ToBytes(pLen, p, 2);
	Utility::MemUtils::Copy<byte, byte>(m_pCoeffs, 0, p, 4, pLen);

	return p;
}

NAMESPACE_KEYASYMMETRICEND