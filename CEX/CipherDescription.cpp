#include "CipherDescription.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

CipherDescription::CipherDescription()
	:
	m_cipherType(0),
	m_cipherExtensionType(0),
	m_cipherModeType(0),
	m_ivSize(0),
	m_keySize(0),
	m_paddingType(0)
{
}

CipherDescription::CipherDescription(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType, PaddingModes PaddingType, KeySizes KeySize, IVSizes IvSize)
{
	m_cipherType = static_cast<byte>(CipherType);
	m_cipherExtensionType = static_cast<byte>(CipherExtensionType);
	m_cipherModeType = static_cast<byte>(CipherModeType);
	m_ivSize = static_cast<byte>(IvSize);
	m_keySize = static_cast<ushort>(KeySize);
	m_paddingType = static_cast<byte>(PaddingType);
}

CipherDescription::CipherDescription(CipherDescription* Description)
{
	m_cipherType = static_cast<byte>(Description->CipherType());
	m_cipherExtensionType = static_cast<byte>(Description->CipherExtensionType());
	m_cipherModeType = static_cast<byte>(Description->CipherModeType());
	m_ivSize = static_cast<byte>(Description->IvSize());
	m_keySize = static_cast<ushort>(Description->KeySize());
	m_paddingType = static_cast<byte>(Description->PaddingType());
}

CipherDescription::CipherDescription(const std::vector<byte> &DescriptionArray)
{
	IO::MemoryStream ms(DescriptionArray);
	IO::StreamReader reader(ms);

	m_cipherType = reader.ReadByte();
	m_cipherExtensionType = reader.ReadByte();
	m_cipherModeType = reader.ReadByte();
	m_ivSize = reader.ReadByte();
	m_keySize = reader.ReadInt<ushort>();
	m_paddingType = reader.ReadByte();
}

CipherDescription::CipherDescription(const MemoryStream &DescriptionStream)
{
	IO::StreamReader reader(DescriptionStream);

	m_cipherType = reader.ReadByte();
	m_cipherExtensionType = reader.ReadByte();
	m_cipherModeType = reader.ReadByte();
	m_ivSize = reader.ReadByte();
	m_keySize = reader.ReadInt<ushort>();
	m_paddingType = reader.ReadByte();
}

CipherDescription::~CipherDescription()
{
	Reset();
}

//~~~Accessors~~~//

const BlockCiphers CipherDescription::CipherType()
{ 
	return static_cast<BlockCiphers>(m_cipherType);
}

const BlockCipherExtensions CipherDescription::CipherExtensionType() 
{ 
	return static_cast<BlockCipherExtensions>(m_cipherExtensionType);
}

const CipherModes CipherDescription::CipherModeType()
{
	return static_cast<CipherModes>(m_cipherModeType); 
}

const IVSizes CipherDescription::IvSize() 
{ 
	return static_cast<IVSizes>(m_ivSize);
}

const ushort CipherDescription::KeySize() const
{ 
	return m_keySize; 
}

const PaddingModes CipherDescription::PaddingType() 
{ 
	return static_cast<PaddingModes>(m_paddingType); 
}

//~~~Public Functions~~~//

CipherDescription* CipherDescription::AES128CBC()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K128, IVSizes::V128);
}

CipherDescription* CipherDescription::AES128CTR()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::CTR, PaddingModes::None, KeySizes::K128, IVSizes::V128);
}

CipherDescription* CipherDescription::AES128GCM()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::GCM, PaddingModes::None, KeySizes::K128, IVSizes::V128);
}

CipherDescription* CipherDescription::AES256CBC()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::AES256CTR()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::AES256GCM()
{
	return new CipherDescription(BlockCiphers::Rijndael, BlockCipherExtensions::None, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}


CipherDescription* CipherDescription::RHX256CBC()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RHX256CTR()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RHX256GCM()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RHX512CBC()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::RHX512CTR()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::RHX512GCM()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


CipherDescription* CipherDescription::RSX256CBC()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RSX256CTR()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RSX256GCM()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::RSX512CBC()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::RSX512CTR()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::RSX512GCM()
{
	return new CipherDescription(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


CipherDescription* CipherDescription::SERPENT256CBC()
{
	return new CipherDescription(BlockCiphers::Serpent, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SERPENT256CTR()
{
	return new CipherDescription(BlockCiphers::Serpent, BlockCipherExtensions::None, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SERPENT256GCM()
{
	return new CipherDescription(BlockCiphers::Serpent, BlockCipherExtensions::None, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}


CipherDescription* CipherDescription::SHX256CBC()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SHX256CTR()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SHX256GCM()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SHX512CBC()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::SHX512CTR()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::SHX512GCM()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


CipherDescription* CipherDescription::SSX256CBC()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SSX256CTR()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SSX256GCM()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::SSX512CBC()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::SSX512CTR()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::SSX512GCM()
{
	return new CipherDescription(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


CipherDescription* CipherDescription::TWOFISH256CBC()
{
	return new CipherDescription(BlockCiphers::Twofish, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::TWOFISH256CTR()
{
	return new CipherDescription(BlockCiphers::Twofish, BlockCipherExtensions::None, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::TWOFISH256GCM()
{
	return new CipherDescription(BlockCiphers::Twofish, BlockCipherExtensions::None, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}


CipherDescription* CipherDescription::THX256CBC()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::THX256CTR()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::THX256GCM()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::THX512CBC()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::THX512CTR()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::THX512GCM()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::HKDF256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


CipherDescription* CipherDescription::TSX256CBC()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::TSX256CTR()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::TSX256GCM()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K256, IVSizes::V128);
}

CipherDescription* CipherDescription::TSX512CBC()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::CBC, PaddingModes::PKCS7, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::TSX512CTR()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::CTR, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}

CipherDescription* CipherDescription::TSX512GCM()
{
	return new CipherDescription(BlockCiphers::THX, BlockCipherExtensions::SHAKE256, CipherModes::GCM, PaddingModes::None, KeySizes::K512, IVSizes::V128);
}


int CipherDescription::GetHeaderSize()
{
	return HDR_SIZE;
}

void CipherDescription::Reset()
{
	m_cipherType = 0;
	m_cipherExtensionType = 0;
	m_cipherModeType = 0;
	m_ivSize = 0;
	m_keySize = 0;
	m_paddingType = 0;
}

std::vector<byte> CipherDescription::ToBytes()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_cipherType);
	writer.Write(m_cipherExtensionType);
	writer.Write(m_cipherModeType);
	writer.Write(m_ivSize);
	writer.Write<ushort>(m_keySize);
	writer.Write(m_paddingType);

	return writer.GetBytes();
}

IO::MemoryStream* CipherDescription::ToStream()
{
	IO::StreamWriter writer(GetHeaderSize());

	writer.Write(m_cipherType);
	writer.Write(m_cipherExtensionType);
	writer.Write(m_cipherModeType);
	writer.Write(m_ivSize);
	writer.Write<ushort>(m_keySize);
	writer.Write(m_paddingType);

	return writer.GetStream();
}

int CipherDescription::GetHashCode()
{
	int result = 1;

	result += 31 * m_cipherType;
	result += 31 * m_cipherExtensionType;
	result += 31 * m_cipherModeType;
	result += 31 * m_ivSize;
	result += 31 * m_keySize;
	result += 31 * m_paddingType;

	return result;
}

bool CipherDescription::Equals(CipherDescription &Input)
{
	return (this->GetHashCode() == Input.GetHashCode());
}

NAMESPACE_PROCESSINGEND
