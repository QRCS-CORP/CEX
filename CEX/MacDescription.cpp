#include "MacDescription.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

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

	writer.Write(static_cast<byte>(m_macType));
	writer.Write(static_cast<short>(m_keySize));
	writer.Write(static_cast<byte>(m_ivSize));
	writer.Write(static_cast<byte>(m_hmacEngine));
	writer.Write(static_cast<byte>(m_engineType));
	writer.Write(static_cast<byte>(m_blockSize));
	writer.Write(static_cast<byte>(m_roundCount));
	writer.Write(static_cast<byte>(m_kdfEngine));

	return writer.GetBytes();
}

IO::MemoryStream* MacDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(static_cast<byte>(m_macType));
	writer.Write(static_cast<short>(m_keySize));
	writer.Write(static_cast<byte>(m_ivSize));
	writer.Write(static_cast<byte>(m_hmacEngine));
	writer.Write(static_cast<byte>(m_engineType));
	writer.Write(static_cast<byte>(m_blockSize));
	writer.Write(static_cast<byte>(m_roundCount));
	writer.Write(static_cast<byte>(m_kdfEngine));

	return writer.GetStream();
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

bool MacDescription::Equals(MacDescription &Obj)
{
	if (this->GetHashCode() != Obj.GetHashCode())
		return false;

	return true;
}

NAMESPACE_PROCESSINGEND