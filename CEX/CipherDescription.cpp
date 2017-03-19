#include "CipherDescription.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

CipherDescription CipherDescription::AES128CBC()
{
	return CipherDescription(SymmetricEngines::RHX, 16, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R10, Digests::None);
}

CipherDescription CipherDescription::AES256CBC()
{
	return CipherDescription(SymmetricEngines::RHX, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R14, Digests::None);
}

CipherDescription CipherDescription::AES512CBC()
{
	return CipherDescription(SymmetricEngines::RHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R22, Digests::None);
}

CipherDescription CipherDescription::RHX512CBC()
{
	return CipherDescription(SymmetricEngines::RHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R22, Digests::SHA256);
}

CipherDescription CipherDescription::AES128CTR()
{
	return CipherDescription(SymmetricEngines::RHX, 16, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R10, Digests::None);
}

CipherDescription CipherDescription::AES256CTR()
{
	return CipherDescription(SymmetricEngines::RHX, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R14, Digests::None);
}

CipherDescription CipherDescription::AES512CTR()
{
	return CipherDescription(SymmetricEngines::RHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R22, Digests::None);
}

CipherDescription CipherDescription::RHX512CTR()
{
	return CipherDescription(SymmetricEngines::RHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R22, Digests::SHA256);
}

CipherDescription CipherDescription::SPT256CBC()
{
	return CipherDescription(SymmetricEngines::SHX, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R32, Digests::None);
}

CipherDescription CipherDescription::SPT512CBC()
{
	return CipherDescription(SymmetricEngines::SHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R40, Digests::None);
}

CipherDescription CipherDescription::SHX512CBC()
{
	return CipherDescription(SymmetricEngines::SHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R40, Digests::SHA256);
}

CipherDescription CipherDescription::SPT256CTR()
{
	return CipherDescription(SymmetricEngines::SHX, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R32, Digests::None);
}

CipherDescription CipherDescription::SPT512CTR()
{
	return CipherDescription(SymmetricEngines::SHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R40, Digests::None);
}

CipherDescription CipherDescription::SHX512CTR()
{
	return CipherDescription(SymmetricEngines::SHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R40, Digests::SHA256);
}

CipherDescription CipherDescription::TFH256CBC()
{
	return CipherDescription(SymmetricEngines::THX, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R16, Digests::None);
}

CipherDescription CipherDescription::TFH512CBC()
{
	return CipherDescription(SymmetricEngines::THX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R20, Digests::None);
}

CipherDescription CipherDescription::THX512CBC()
{
	return CipherDescription(SymmetricEngines::THX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R20, Digests::SHA256);
}

CipherDescription CipherDescription::TFH256CTR()
{
	return CipherDescription(SymmetricEngines::THX, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R16, Digests::None);
}

CipherDescription CipherDescription::TFH512CTR()
{
	return CipherDescription(SymmetricEngines::THX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R20, Digests::None);
}

CipherDescription CipherDescription::THX512CTR()
{
	return CipherDescription(SymmetricEngines::THX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R20, Digests::SHA256);
}

int CipherDescription::GetHeaderSize()
{
	return HDR_SIZE;
}

void CipherDescription::Reset()
{
	m_engineType = 0;
	m_keySize = 0;
	m_ivSize = 0;
	m_cipherType = 0;
	m_paddingType = 0;
	m_blockSize = 0;
	m_roundCount = 0;
	m_kdfEngine = 0;
}

std::vector<byte> CipherDescription::ToBytes()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(static_cast<byte>(m_engineType));
	writer.Write(static_cast<short>(m_keySize));
	writer.Write(static_cast<byte>(m_ivSize));
	writer.Write(static_cast<byte>(m_cipherType));
	writer.Write(static_cast<byte>(m_paddingType));
	writer.Write(static_cast<byte>(m_blockSize));
	writer.Write(static_cast<byte>(m_roundCount));
	writer.Write(static_cast<byte>(m_kdfEngine));

	return writer.GetBytes();
}

IO::MemoryStream* CipherDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(static_cast<byte>(m_engineType));
	writer.Write(static_cast<short>(m_keySize));
	writer.Write(static_cast<byte>(m_ivSize));
	writer.Write(static_cast<byte>(m_cipherType));
	writer.Write(static_cast<byte>(m_paddingType));
	writer.Write(static_cast<byte>(m_blockSize));
	writer.Write(static_cast<byte>(m_roundCount));
	writer.Write(static_cast<byte>(m_kdfEngine));

	return writer.GetStream();
}

int CipherDescription::GetHashCode()
{
	int result = 1;

	result += 31 * m_engineType;
	result += 31 * m_keySize;
	result += 31 * m_ivSize;
	result += 31 * m_cipherType;
	result += 31 * m_paddingType;
	result += 31 * m_blockSize;
	result += 31 * m_roundCount;
	result += 31 * m_kdfEngine;

	return result;
}

bool CipherDescription::Equals(CipherDescription &Obj)
{
	if (this->GetHashCode() != Obj.GetHashCode())
		return false;

	return true;
}

NAMESPACE_PROCESSINGEND