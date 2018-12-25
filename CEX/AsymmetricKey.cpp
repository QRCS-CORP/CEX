#include "AsymmetricKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

using Utility::IntUtils;
using Utility::MemUtils;

AsymmetricKey::AsymmetricKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P)
	:
	m_cipherEngine(CipherType != AsymmetricEngines::None ? CipherType :
		throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher engine type can not be None!")),
	m_cipherKey(CipherKeyType != AsymmetricKeyTypes::None ? CipherKeyType :
		throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher key type can not be None!")),
	m_cipherParams(ParameterType != AsymmetricTransforms::None ? ParameterType :
		throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The cipher parameters type can not be None!")),
	m_isDestroyed(false),
	m_polyCoeffs(P.size() != 0 ? P :
		throw CryptoAsymmetricException("AsymmetricKey::Ctor", "The polynomial array can not be zero length!"))
{
}

AsymmetricKey::AsymmetricKey(const std::vector<byte> &KeyStream)
	:
	m_cipherEngine(static_cast<AsymmetricEngines>(KeyStream[0])),
	m_cipherKey(static_cast<AsymmetricKeyTypes>(KeyStream[1])),
	m_cipherParams(static_cast<AsymmetricTransforms>(KeyStream[2])),
	m_isDestroyed(false),
	m_polyCoeffs(KeyStream.begin() + 7, KeyStream.begin() + 7 + IntUtils::LeBytesTo32(KeyStream, 3))
{
}

AsymmetricKey::~AsymmetricKey()
{
	Destroy();
}

const AsymmetricEngines AsymmetricKey::CipherType()
{
	return m_cipherEngine;
}

const AsymmetricKeyTypes AsymmetricKey::KeyType()
{
	return m_cipherKey;
}

const AsymmetricTransforms AsymmetricKey::Parameters()
{
	return m_cipherParams;
}

const std::vector<byte> &AsymmetricKey::P()
{
	return m_polyCoeffs;
}

void AsymmetricKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherEngine = AsymmetricEngines::None;
		m_cipherKey = AsymmetricKeyTypes::None;
		m_cipherParams = AsymmetricTransforms::None;

		if (m_polyCoeffs.size() > 0)
		{
			IntUtils::ClearVector(m_polyCoeffs);
		}
	}
}

std::vector<byte> AsymmetricKey::ToBytes()
{
	const uint PLYLEN = static_cast<uint>(m_polyCoeffs.size());
	std::vector<byte> poly(PLYLEN + 7);

	poly[0] = static_cast<byte>(m_cipherEngine);
	poly[1] = static_cast<byte>(m_cipherKey);
	poly[2] = static_cast<byte>(m_cipherParams);
	IntUtils::Le32ToBytes(PLYLEN, poly, 3);
	MemUtils::Copy(m_polyCoeffs, 0, poly, 7, PLYLEN);

	return poly;
}

NAMESPACE_ASYMMETRICKEYEND
