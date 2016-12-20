#include "SecureStream.h"
#include "ArrayUtils.h"
#include "CTR.h"
#include "SHA512.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_IO

//~~~Public Methods~~~//

void SecureStream::Close()
{
	m_streamData.clear();
	m_streamPosition = 0;
}

void SecureStream::CopyTo(IByteStream* Destination)
{
	Transform();
	Destination->Write(m_streamData, 0, m_streamData.size());
	Transform();
}

void SecureStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_streamPosition = 0;
		Utility::ArrayUtils::ClearVector(m_streamData);
		m_isDestroyed = true;
	}
}

size_t SecureStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > m_streamData.size() - m_streamPosition)
		Length = m_streamData.size() - m_streamPosition;

	if (Length > 0)
	{
		Transform();
		memcpy(&Output[Offset], &m_streamData[m_streamPosition], Length);
		Transform();
		m_streamPosition += Length;
	}

	return Length;
}

byte SecureStream::ReadByte()
{
	if (m_streamData.size() - m_streamPosition < 1)
		throw CryptoProcessingException("SecureStream:ReadByte", "The output array is too short!");

	byte data(1);
	Transform();
	memcpy(&data, &m_streamData[m_streamPosition], 1);
	Transform();
	m_streamPosition += 1;

	return data;
}

void SecureStream::Reset()
{
	m_streamData.clear();
	m_streamData.resize(0);
	m_streamPosition = 0;
}

void SecureStream::Seek(uint64_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		m_streamPosition = Offset;
	else if (Origin == SeekOrigin::End)
		m_streamPosition = m_streamData.size() - Offset;
	else
		m_streamPosition += Offset;
}

void SecureStream::SetLength(uint64_t Length)
{
	m_streamData.reserve(Length);
}

void SecureStream::Write(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Offset + Length > Input.size())
		throw CryptoProcessingException("SecureStream:Write", "The input array is too short!");

	size_t len = m_streamPosition + Length;
	if (m_streamData.capacity() - m_streamPosition < Length)
		m_streamData.reserve(len);
	if (m_streamData.size() < len)
		m_streamData.resize(len);

	Transform();
	memcpy(&m_streamData[m_streamPosition], &Input[Offset], Length);
	Transform();
	m_streamPosition += Length;
}

void SecureStream::WriteByte(byte Value)
{
	if (m_streamData.size() - m_streamPosition < 1)
		m_streamData.resize(m_streamData.size() + 1);

	Transform();
	memcpy(&m_streamData[m_streamPosition], &Value, 1);
	Transform();
	m_streamPosition += 1;
}

//~~~Private Methods~~~//

std::vector<byte> SecureStream::GetSystemKey()
{
	std::vector<byte> state(0);
	Utility::ArrayUtils::Append(Utility::SysUtils::ComputerName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::OsName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserId(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::UserName(), state);

	if (m_keySalt.size() != 0)
		Utility::ArrayUtils::Append(m_keySalt, state);

	Digest::SHA512 dgt;
	std::vector<byte> hash(dgt.DigestSize());
	dgt.Compute(state, hash);

	return hash;
}

void SecureStream::Transform()
{
	if (m_streamData.size() == 0)
		return;

	std::vector<byte> seed = GetSystemKey();
	std::vector<byte> key(32);
	std::vector<byte> iv(16);

	memcpy(&key[0], &seed[0], key.size());
	memcpy(&iv[0], &seed[key.size()], iv.size());
	Key::Symmetric::SymmetricKey kp(key, iv);

	// AES256-CTR
	Cipher::Symmetric::Block::Mode::CTR cpr(Enumeration::BlockCiphers::Rijndael);
	cpr.Initialize(true, kp);
	std::vector<byte> state(m_streamData.size());
	cpr.Transform(m_streamData, state);
	m_streamData = state;
}

NAMESPACE_IOEND