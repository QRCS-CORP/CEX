#include "SecureStream.h"
#include "ArrayUtils.h"
#include "CTR.h"
#include "SHA512.h"
#include "SymmetricKey.h"
#include "SysUtils.h"

NAMESPACE_IO

const std::string SecureStream::CLASS_NAME("SecureStream");

//~~~Constructor~~~//

SecureStream::SecureStream()
	:
	m_isDestroyed(false),
	m_keySalt(0),
	m_streamData(0),
	m_streamPosition(0)
{
}

SecureStream::SecureStream(size_t Length, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySalt(KeySalt),
	m_streamData(0),
	m_streamPosition(0)
{
	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::MemUtils::CopyFromValue(KeySalt, m_keySalt, 0, sizeof(ulong));
	}

	m_streamData.reserve(Length);
}

SecureStream::SecureStream(const std::vector<byte> &Data, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySalt(KeySalt),
	m_streamData(Data),
	m_streamPosition(0)
{
	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::MemUtils::CopyFromValue(KeySalt, m_keySalt, 0, sizeof(ulong));
	}

	Transform();
}

SecureStream::SecureStream(std::vector<byte> &Data, size_t Offset, size_t Length, ulong KeySalt)
	:
	m_isDestroyed(false),
	m_keySalt(KeySalt),
	m_streamData(0),
	m_streamPosition(0)
{
	CexAssert(Length <= Data.size() - Offset, "length is longer than the array size");

	m_streamData.resize(Length);
	Utility::MemUtils::Copy(Data, Offset, m_streamData, 0, Length);

	if (KeySalt != 0)
	{
		m_keySalt.resize(sizeof(ulong));
		Utility::MemUtils::CopyFromValue(KeySalt, m_keySalt, 0, sizeof(ulong));
	}

	Transform();
}

SecureStream::~SecureStream()
{
	Destroy();
}

//~~~Accessors~~~//

const bool SecureStream::CanRead() 
{ 
	return true; 
}

const bool SecureStream::CanSeek() 
{ 
	return true; 
}

const bool SecureStream::CanWrite() 
{ 
	return true; 
}

const StreamModes SecureStream::Enumeral() 
{ 
	return StreamModes::SecureStream; 
}

const ulong SecureStream::Length() 
{ 
	return static_cast<ulong>(m_streamData.size());
}

const std::string SecureStream::Name()
{
	return CLASS_NAME;
}

const ulong SecureStream::Position() 
{ 
	return m_streamPosition; 
}

//~~~Public Functions~~~//

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
		m_isDestroyed = true;
		m_streamPosition = 0;
		Utility::IntUtils::ClearVector(m_streamData);
	}
}

size_t SecureStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > m_streamData.size() - m_streamPosition)
	{
		Length = m_streamData.size() - m_streamPosition;
	}

	if (Length > 0)
	{
		Transform();
		Utility::MemUtils::Copy(m_streamData, m_streamPosition, Output, Offset, Length);
		Transform();
		m_streamPosition += Length;
	}

	return Length;
}

byte SecureStream::ReadByte()
{
	CexAssert(m_streamData.size() - m_streamPosition >= 1, "Stream capacity exceeded");

	byte data = 0;
	Transform();
	Utility::MemUtils::CopyToValue(m_streamData, m_streamPosition, data, 1);
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

void SecureStream::Seek(ulong Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
	{
		m_streamPosition = Offset;
	}
	else if (Origin == SeekOrigin::End)
	{
		m_streamPosition = m_streamData.size() - Offset;
	}
	else
	{
		m_streamPosition += Offset;
	}
}

void SecureStream::SetLength(ulong Length)
{
	m_streamData.reserve(Length);
}

std::vector<byte> SecureStream::ToArray()
{
	if (m_streamData.size() == 0)
	{
		return std::vector<byte>(0);
	}

	Transform();
	std::vector<byte> tmp = m_streamData;
	Transform();

	return tmp;
}

void SecureStream::Write(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Input.size(), "length is longer than the array size");

	size_t len = m_streamPosition + Length;
	if (m_streamData.capacity() - m_streamPosition < Length)
	{
		m_streamData.reserve(len);
	}
	if (m_streamData.size() < len)
	{
		m_streamData.resize(len);
	}

	Transform();
	Utility::MemUtils::Copy(Input, Offset, m_streamData, m_streamPosition, Length);
	Transform();
	m_streamPosition += Length;
}

void SecureStream::WriteByte(byte Value)
{
	if (m_streamData.size() - m_streamPosition < 1)
	{
		m_streamData.resize(m_streamData.size() + 1);
	}

	Transform();
	Utility::MemUtils::CopyFromValue(Value, m_streamData, m_streamPosition, 1);
	Transform();
	m_streamPosition += 1;
}

//~~~Private Functions~~~//

std::vector<byte> SecureStream::GetSystemKey()
{
	std::vector<byte> state(0);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::ComputerName(), state);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::OsName(), state);
	Utility::ArrayUtils::Append(Utility::SysUtils::ProcessId(), state);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::UserId(), state);
	Utility::ArrayUtils::AppendString(Utility::SysUtils::UserName(), state);

	if (m_keySalt.size() != 0)
	{
		Utility::ArrayUtils::Append(m_keySalt, state);
	}

	Digest::SHA512 dgt;
	std::vector<byte> hash(dgt.DigestSize());
	dgt.Compute(state, hash);

	return hash;
}

void SecureStream::Transform()
{
	if (m_streamData.size() != 0)
	{
		std::vector<byte> seed = GetSystemKey();
		std::vector<byte> key(32);
		std::vector<byte> iv(16);

		Utility::MemUtils::Copy(seed, 0, key, 0, key.size());
		Utility::MemUtils::Copy(seed, key.size(), iv, 0, iv.size());
		Key::Symmetric::SymmetricKey kp(key, iv);

		// AES256-CTR
		Cipher::Symmetric::Block::Mode::CTR cpr(Enumeration::BlockCiphers::Rijndael);
		cpr.Initialize(true, kp);
		std::vector<byte> state(m_streamData.size());
		cpr.Transform(m_streamData, 0, state, 0, state.size());
		m_streamData = state;
	}
}

NAMESPACE_IOEND
