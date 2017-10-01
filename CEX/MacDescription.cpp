#include "MacDescription.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

//~~~Properties~~~//

const BlockSizes MacDescription::BlockSize() 
{
	return static_cast<BlockSizes>(m_blockSize);
}

const BlockCiphers MacDescription::EngineType() 
{ 
	return static_cast<BlockCiphers>(m_engineType); 
}

const Digests MacDescription::HmacEngine() 
{ 
	return static_cast<Digests>(m_hmacEngine); 
}

const IVSizes MacDescription::IvSize() 
{ 
	return static_cast<IVSizes>(m_ivSize); 
}

const Digests MacDescription::KdfEngine()
{
	return static_cast<Digests>(m_kdfEngine);
}

const short MacDescription::KeySize() 
{ 
	return m_keySize;
}

const Macs MacDescription::MacType()
{ 
	return static_cast<Macs>(m_macType);
}

const RoundCounts MacDescription::RoundCount() 
{ 
	return static_cast<RoundCounts>(m_roundCount);
}

//~~~Presets~~~//

MacDescription MacDescription::HMACSHA256()
{
	return MacDescription(64, Digests::SHA256);
}

MacDescription MacDescription::HMACSHA512()
{
	return MacDescription(128, Digests::SHA512);
}

MacDescription MacDescription::CMACAES256()
{
	return MacDescription(32, BlockCiphers::Rijndael, IVSizes::V128);
}

int MacDescription::GetHeaderSize()
{
	return MACHDR_SIZE;
}

//~~~Constructor~~~//

MacDescription::MacDescription()
	:
	m_macType(0),
	m_keySize(0),
	m_ivSize(0),
	m_hmacEngine(0),
	m_engineType(0),
	m_blockSize(0),
	m_roundCount(0),
	m_kdfEngine(0)
{}

MacDescription::MacDescription(Macs MacType, short KeySize, byte IvSize, Digests HmacEngine, BlockCiphers EngineType, BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine)
{
	m_macType = static_cast<byte>(MacType);
	m_keySize = KeySize;
	m_ivSize = IvSize;
	m_hmacEngine = static_cast<byte>(HmacEngine);
	m_engineType = static_cast<byte>(EngineType);
	m_blockSize = static_cast<byte>(BlockSize);
	m_roundCount = static_cast<byte>(RoundCount);
	m_kdfEngine = static_cast<byte>(KdfEngine);
}

MacDescription::MacDescription(uint KeySize, Digests HmacEngine)
{
	m_macType = static_cast<byte>(Macs::HMAC);
	m_keySize = KeySize;
	m_hmacEngine = static_cast<byte>(HmacEngine);
	m_ivSize = 0;
	m_engineType = 0;
	m_blockSize = 0;
	m_roundCount = 0;
	m_kdfEngine = 0;
}

MacDescription::MacDescription(short KeySize, BlockCiphers EngineType, IVSizes IvSize, BlockSizes BlockSize, RoundCounts RoundCount, Digests KdfEngine)
{
	m_macType = static_cast<byte>(Macs::CMAC);
	m_keySize = KeySize;
	m_ivSize = static_cast<byte>(IvSize);
	m_hmacEngine = 0;
	m_engineType = static_cast<byte>(EngineType);
	m_blockSize = static_cast<byte>(BlockSize);
	m_roundCount = static_cast<byte>(RoundCount);
	m_kdfEngine = static_cast<byte>(KdfEngine);
}

MacDescription::MacDescription(const MemoryStream &DescriptionStream)
{
	IO::StreamReader reader(DescriptionStream);

	m_macType = reader.ReadByte();
	m_keySize = reader.ReadInt<short>();
	m_ivSize = reader.ReadByte();
	m_hmacEngine = reader.ReadByte();
	m_engineType = reader.ReadByte();
	m_blockSize = reader.ReadByte();
	m_roundCount = reader.ReadByte();
	m_kdfEngine = reader.ReadByte();
}

MacDescription::MacDescription(const std::vector<byte> &DescriptionArray)
{
	MemoryStream ms = MemoryStream(DescriptionArray);
	IO::StreamReader reader(ms);

	m_macType = reader.ReadByte();
	m_keySize = reader.ReadInt<short>();
	m_ivSize = reader.ReadByte();
	m_hmacEngine = reader.ReadByte();
	m_engineType = reader.ReadByte();
	m_blockSize = reader.ReadByte();
	m_roundCount = reader.ReadByte();
	m_kdfEngine = reader.ReadByte();
}

//~~~Public Functions~~~//

bool MacDescription::Equals(MacDescription &Input)
{
	if (this->GetHashCode() != Input.GetHashCode())
		return false;

	return true;
}

int MacDescription::GetHashCode()
{
	int hash = 31 * m_macType;
	hash += 31 * m_keySize;
	hash += 31 * m_ivSize;
	hash += 31 * m_hmacEngine;
	hash += 31 * m_engineType;
	hash += 31 * m_blockSize;
	hash += 31 * m_roundCount;
	hash += 31 * m_kdfEngine;

	return hash;
}

void MacDescription::Reset()
{
	m_macType = 0;
	m_keySize = 0;
	m_ivSize = 0;
	m_hmacEngine = 0;
	m_engineType = 0;
	m_blockSize = 0;
	m_roundCount = 0;
	m_kdfEngine = 0;
}

std::vector<byte> MacDescription::ToBytes()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_macType);
	writer.Write<short>(m_keySize);
	writer.Write(m_ivSize);
	writer.Write(m_hmacEngine);
	writer.Write(m_engineType);
	writer.Write(m_blockSize);
	writer.Write(m_roundCount);
	writer.Write(m_kdfEngine);

	return writer.GetBytes();
}

IO::MemoryStream* MacDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_macType);
	writer.Write<short>(m_keySize);
	writer.Write(m_ivSize);
	writer.Write(m_hmacEngine);
	writer.Write(m_engineType);
	writer.Write(m_blockSize);
	writer.Write(m_roundCount);
	writer.Write(m_kdfEngine);

	return writer.GetStream();
}

NAMESPACE_PROCESSINGEND