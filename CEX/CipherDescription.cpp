#include "CipherDescription.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

CipherDescription::CipherDescription()
	:
	m_engineType(0),
	m_keySize(0),
	m_ivSize(0),
	m_cipherType(0),
	m_paddingType(0),
	m_blockSize(0),
	m_roundCount(0),
	m_kdfEngine(0)
{
}

CipherDescription::CipherDescription(BlockCiphers EngineType, short KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine)
{
	m_engineType = static_cast<byte>(EngineType);
	m_keySize = KeySize;
	m_ivSize = static_cast<byte>(IvSize);
	m_cipherType = static_cast<byte>(CipherType);
	m_paddingType = static_cast<byte>(PaddingType);
	m_blockSize = static_cast<byte>(BlockSize);
	m_roundCount = static_cast<byte>(RoundCount);
	m_kdfEngine = static_cast<byte>(KdfEngine);
}

CipherDescription::CipherDescription(const std::vector<byte> &DescriptionArray)
{
	IO::MemoryStream ms(DescriptionArray);
	IO::StreamReader reader(ms);

	m_engineType = reader.ReadByte();
	m_keySize = reader.ReadInt<short>();
	m_ivSize = reader.ReadByte();
	m_cipherType = reader.ReadByte();
	m_paddingType = reader.ReadByte();
	m_blockSize = reader.ReadByte();
	m_roundCount = reader.ReadByte();
	m_kdfEngine = reader.ReadByte();
}

CipherDescription::CipherDescription(const MemoryStream &DescriptionStream)
{
	IO::StreamReader reader(DescriptionStream);

	m_engineType = reader.ReadByte();
	m_keySize = reader.ReadInt<short>();
	m_ivSize = reader.ReadByte();
	m_cipherType = reader.ReadByte();
	m_paddingType = reader.ReadByte();
	m_blockSize = reader.ReadByte();
	m_roundCount = reader.ReadByte();
	m_kdfEngine = reader.ReadByte();
}

CipherDescription::~CipherDescription()
{
	Reset();
}

//~~~Accessors~~~//

const BlockCiphers CipherDescription::EngineType()
{ 
	return static_cast<BlockCiphers>(m_engineType);
}

const short CipherDescription::KeySize() const
{ 
	return m_keySize; 
}

short &CipherDescription::KeySize()
{ 
	return m_keySize; 
}

const IVSizes CipherDescription::IvSize() 
{ 
	return static_cast<IVSizes>(m_ivSize);
}

const CipherModes CipherDescription::CipherType()
{
	return static_cast<CipherModes>(m_cipherType); 
}

const PaddingModes CipherDescription::PaddingType() 
{ 
	return static_cast<PaddingModes>(m_paddingType); 
}

const BlockSizes CipherDescription::BlockSize()
{ 
	return static_cast<BlockSizes>(m_blockSize); 
}

const RoundCounts CipherDescription::RoundCount()
{ 
	return static_cast<RoundCounts>(m_roundCount);
}

const Digests CipherDescription::KdfEngine() 
{ 
	return static_cast<Digests>(m_kdfEngine);
}

//~~~Public Functions~~~//

CipherDescription CipherDescription::AES128CBC()
{
	return CipherDescription(BlockCiphers::Rijndael, 16, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R10, Digests::None);
}

CipherDescription CipherDescription::AES256CBC()
{
	return CipherDescription(BlockCiphers::Rijndael, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R14, Digests::None);
}

CipherDescription CipherDescription::RHX512CBC()
{
	return CipherDescription(BlockCiphers::RHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R22, Digests::SHA256);
}

CipherDescription CipherDescription::AES128CTR()
{
	return CipherDescription(BlockCiphers::Rijndael, 16, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R10, Digests::None);
}

CipherDescription CipherDescription::AES256CTR()
{
	return CipherDescription(BlockCiphers::Rijndael, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R14, Digests::None);
}

CipherDescription CipherDescription::RHX512CTR()
{
	return CipherDescription(BlockCiphers::RHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R22, Digests::SHA256);
}

CipherDescription CipherDescription::SERPENT256CBC()
{
	return CipherDescription(BlockCiphers::Serpent, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R32, Digests::None);
}

CipherDescription CipherDescription::SHX512CBC()
{
	return CipherDescription(BlockCiphers::SHX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R40, Digests::SHA256);
}

CipherDescription CipherDescription::SERPENT256CTR()
{
	return CipherDescription(BlockCiphers::Serpent, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R32, Digests::None);
}

CipherDescription CipherDescription::SHX512CTR()
{
	return CipherDescription(BlockCiphers::SHX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R40, Digests::SHA256);
}

CipherDescription CipherDescription::TWOFISH256CBC()
{
	return CipherDescription(BlockCiphers::Twofish, 32, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R16, Digests::None);
}

CipherDescription CipherDescription::THX512CBC()
{
	return CipherDescription(BlockCiphers::THX, 64, IVSizes::V128, CipherModes::CBC, PaddingModes::PKCS7, BlockSizes::B128, RoundCounts::R20, Digests::SHA256);
}

CipherDescription CipherDescription::TWOFISH256CTR()
{
	return CipherDescription(BlockCiphers::Twofish, 32, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R16, Digests::None);
}

CipherDescription CipherDescription::THX512CTR()
{
	return CipherDescription(BlockCiphers::THX, 64, IVSizes::V128, CipherModes::CTR, PaddingModes::None, BlockSizes::B128, RoundCounts::R20, Digests::SHA256);
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

	writer.Write(m_engineType);
	writer.Write<short>(m_keySize);
	writer.Write(m_ivSize);
	writer.Write(m_cipherType);
	writer.Write(m_paddingType);
	writer.Write(m_blockSize);
	writer.Write(m_roundCount);
	writer.Write(m_kdfEngine);

	return writer.GetBytes();
}

IO::MemoryStream* CipherDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_engineType);
	writer.Write<short>(m_keySize);
	writer.Write(m_ivSize);
	writer.Write(m_cipherType);
	writer.Write(m_paddingType);
	writer.Write(m_blockSize);
	writer.Write(m_roundCount);
	writer.Write(m_kdfEngine);

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

bool CipherDescription::Equals(CipherDescription &Input)
{
	return (this->GetHashCode() == Input.GetHashCode());
}

NAMESPACE_PROCESSINGEND