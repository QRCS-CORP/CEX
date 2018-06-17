#include "MacDescription.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

MacDescription::MacDescription()
	:
	m_blockCipher(0),
	m_cipherExtension(0),
	m_macDigest(0),
	m_macType(0)
{
}

MacDescription::MacDescription(Macs MacType, BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType)
	:
	m_blockCipher(static_cast<byte>(CipherType)),
	m_cipherExtension(static_cast<byte>(CipherExtensionType)),
	m_macDigest(0),
	m_macType(static_cast<byte>(MacType))
{
}

MacDescription::MacDescription(Macs MacType, Digests MacDigestType)
	:
	m_blockCipher(0),
	m_cipherExtension(0),
	m_macDigest(static_cast<byte>(MacDigestType)),
	m_macType(static_cast<byte>(MacType))
{
}

MacDescription::MacDescription(const MemoryStream &DescriptionStream)
{
	IO::StreamReader reader(DescriptionStream);

	m_blockCipher = reader.ReadByte();
	m_cipherExtension = reader.ReadByte();
	m_macDigest = reader.ReadByte();
	m_macType = reader.ReadByte();
}

MacDescription::MacDescription(const std::vector<byte> &DescriptionArray)
{
	MemoryStream ms(DescriptionArray);
	IO::StreamReader reader(ms);

	m_blockCipher = reader.ReadByte();
	m_cipherExtension = reader.ReadByte();
	m_macDigest = reader.ReadByte();
	m_macType = reader.ReadByte();
}

//~~~Accessors~~~//

const BlockCipherExtensions MacDescription::CipherExtension()
{
	return static_cast<BlockCipherExtensions>(m_cipherExtension);
}

const BlockCiphers MacDescription::CipherType() 
{ 
	return static_cast<BlockCiphers>(m_blockCipher);
}

const Digests MacDescription::MacDigest() 
{ 
	return static_cast<Digests>(m_macDigest);
}

const Macs MacDescription::MacType()
{ 
	return static_cast<Macs>(m_macType);
}

//~~~Presets~~~//

int MacDescription::GetHeaderSize()
{
	return MACHDR_SIZE;
}

//~~~Public Functions~~~//

bool MacDescription::Equals(MacDescription &Input)
{
	return (this->GetHashCode() == Input.GetHashCode());
}

int MacDescription::GetHashCode()
{
	int hash = 31 * m_blockCipher;
	hash += 31 * m_cipherExtension;
	hash += 31 * m_macDigest;
	hash += 31 * m_macType;

	return hash;
}

void MacDescription::Reset()
{
	m_blockCipher = 0;
	m_cipherExtension = 0;
	m_macDigest = 0;
	m_macType = 0;
}

std::vector<byte> MacDescription::ToBytes()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_blockCipher);
	writer.Write(m_cipherExtension);
	writer.Write(m_macDigest);
	writer.Write(m_macType);

	return writer.Generate();
}

IO::MemoryStream* MacDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_blockCipher);
	writer.Write(m_cipherExtension);
	writer.Write(m_macDigest);
	writer.Write(m_macType);

	return writer.GetStream();
}

NAMESPACE_PROCESSINGEND
