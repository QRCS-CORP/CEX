#include "PicnicPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

PicnicPrivateKey::PicnicPrivateKey(PicnicParams Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_picnicParameters(Parameters),
	m_rCoeffs(R)
{
}

PicnicPrivateKey::PicnicPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_picnicParameters(PicnicParams::None),
	m_rCoeffs(0)
{
	m_picnicParameters = static_cast<PicnicParams>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
	{
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
	}
}

PicnicPrivateKey::~PicnicPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines PicnicPrivateKey::CipherType()
{
	return AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes PicnicPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const PicnicParams PicnicPrivateKey::Parameters()
{
	return m_picnicParameters;
}

const std::vector<byte> &PicnicPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void PicnicPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_picnicParameters = PicnicParams::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> PicnicPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_picnicParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
	{
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));
	}

	return r;
}

NAMESPACE_ASYMMETRICKEYEND
