#include "MPKCPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Properties~~~//

const AsymmetricEngines MPKCPrivateKey::CipherType()
{
	return AsymmetricEngines::McEliece;
}

const MPKCParams MPKCPrivateKey::Parameters()
{
	return m_mpkcParameters;
}

const std::vector<byte> &MPKCPrivateKey::S()
{
	return m_sCoeffs;
}

//~~~Constructor~~~//

MPKCPrivateKey::MPKCPrivateKey(MPKCParams Parameters, std::vector<byte> &S)
	:
	m_isDestroyed(false),
	m_mpkcParameters(Parameters),
	m_sCoeffs(S)
{
}

MPKCPrivateKey::MPKCPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_mpkcParameters(MPKCParams::None),
	m_sCoeffs(0)
{
	m_mpkcParameters = static_cast<MPKCParams>(Utility::IntUtils::LeBytesTo16(KeyStream, 0));
	uint sLen = Utility::IntUtils::LeBytesTo16(KeyStream, 2);
	m_sCoeffs.resize(sLen);
	Utility::MemUtils::Copy<byte, byte>(KeyStream, 4, m_sCoeffs, 0, sLen);
}

MPKCPrivateKey::~MPKCPrivateKey()
{
	Destroy();
}

//~~~Public Functions~~~//

void MPKCPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_mpkcParameters = MPKCParams::None;

		if (m_sCoeffs.size() > 0)
			Utility::IntUtils::ClearVector(m_sCoeffs);

		m_isDestroyed = true;
	}
}

std::vector<byte> MPKCPrivateKey::ToBytes()
{
	ushort sLen = static_cast<ushort>(m_sCoeffs.size());
	std::vector<byte> s(sLen + 4);
	Utility::IntUtils::Le16ToBytes(static_cast<ushort>(m_mpkcParameters), s, 0);
	Utility::IntUtils::Le16ToBytes(sLen, s, 2);
	Utility::MemUtils::Copy<byte, byte>(s, 4, m_sCoeffs, 0, sLen);

	return s;
}

NAMESPACE_ASYMMETRICKEYEND