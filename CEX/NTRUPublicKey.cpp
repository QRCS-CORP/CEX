#include "NTRUPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

NTRUPublicKey::NTRUPublicKey(NTRUParameters Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_ntruParameters(Parameters),
	m_pCoeffs(P)
{
}

NTRUPublicKey::NTRUPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_ntruParameters(NTRUParameters::None),
	m_pCoeffs(0)
{
	m_ntruParameters = static_cast<NTRUParameters>(KeyStream[0]);
	uint pLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_pCoeffs, 0, pLen);
}

NTRUPublicKey::~NTRUPublicKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines NTRUPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes NTRUPublicKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPublicKey;
}

const NTRUParameters NTRUPublicKey::Parameters()
{
	return m_ntruParameters;
}

const std::vector<byte> &NTRUPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Public Functions~~~//

void NTRUPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_ntruParameters = NTRUParameters::None;

		if (m_pCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_pCoeffs);
		}
	}
}

std::vector<byte> NTRUPublicKey::ToBytes()
{
	uint pLen = static_cast<uint>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 5);

	p[0] = static_cast<byte>(m_ntruParameters);
	Utility::IntUtils::Le32ToBytes(pLen, p, 1);
	Utility::MemUtils::Copy(m_pCoeffs, 0, p, 5, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND
