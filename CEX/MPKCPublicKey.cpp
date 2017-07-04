#include "MPKCPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Properties~~~//

const AsymmetricEngines MPKCPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::McEliece;
}

const MPKCParams MPKCPublicKey::Parameters()
{
	return m_mpkcParameters;
}

const std::vector<byte> &MPKCPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Constructor~~~//

MPKCPublicKey::MPKCPublicKey(MPKCParams Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_mpkcParameters(Parameters),
	m_pCoeffs(P)
{
}

MPKCPublicKey::MPKCPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_mpkcParameters(MPKCParams::None),
	m_pCoeffs(0)
{
	m_mpkcParameters = static_cast<MPKCParams>(Utility::IntUtils::LeBytesTo16(KeyStream, 0));
	uint pLen = Utility::IntUtils::LeBytesTo16(KeyStream, 2);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy<byte, byte>(KeyStream, 4, m_pCoeffs, 0, pLen);
}

MPKCPublicKey::~MPKCPublicKey()
{
	Destroy();
}

//~~~Public Functions~~~//

void MPKCPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_mpkcParameters = MPKCParams::None;

		if (m_pCoeffs.size() > 0)
			Utility::IntUtils::ClearVector(m_pCoeffs);

		m_isDestroyed = true;
	}
}

std::vector<byte> MPKCPublicKey::ToBytes()
{
	ushort pLen = static_cast<ushort>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 4);
	Utility::IntUtils::Le16ToBytes(static_cast<ushort>(m_mpkcParameters), p, 0);
	Utility::IntUtils::Le16ToBytes(pLen, p, 2);
	Utility::MemUtils::Copy<byte, byte>(m_pCoeffs, 0, p, 4, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND