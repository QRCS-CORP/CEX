#include "MemoryStream.h"
#include "IntUtils.h"

NAMESPACE_IO

void MemoryStream::Close()
{
	throw CryptoProcessingException("MemoryStream:Flush", "Not implemented in MemoryStream!");
}

void MemoryStream::CopyTo(IByteStream* Destination)
{
	Destination->Write(_streamData, 0, _streamData.size());
}

void MemoryStream::Destroy()
{
	if (!_isDestroyed)
	{
		_streamPosition = 0;
		CEX::Utility::IntUtils::ClearVector(_streamData);
		_isDestroyed = true;
	}
}

void MemoryStream::Flush()
{
	throw CryptoProcessingException("MemoryStream:Flush", "Not implemented in MemoryStream!");
}

size_t MemoryStream::Read(std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
	if (Offset + Count > _streamData.size() - _streamPosition)
		Count = _streamData.size() - _streamPosition;

	if (Count > 0)
	{
		memcpy(&Buffer[Offset], &_streamData[_streamPosition], Count);
		_streamPosition += Count;
	}

	return Count;
}

byte MemoryStream::ReadByte()
{
	if (_streamData.size() - _streamPosition < 1)
		throw CryptoProcessingException("MemoryStream:ReadByte", "The output array is too short!");

	byte data(1);
	memcpy(&data, &_streamData[_streamPosition], 1);
	_streamPosition += 1;

	return data;
}

void MemoryStream::Reset()
{
	_streamData.clear();
	_streamData.resize(0);
	_streamPosition = 0;
}

void MemoryStream::Seek(size_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		_streamPosition = Offset;
	else if (Origin == SeekOrigin::End)
		_streamPosition = _streamData.size() - Offset;
	else
		_streamPosition += Offset;
}

void MemoryStream::SetLength(size_t Length)
{
	_streamData.reserve(Length);
}

void MemoryStream::Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
	if (Offset + Count > Buffer.size())
		throw CryptoProcessingException("MemoryStream:Write", "The output array is too short!");

	size_t len = _streamPosition + Count;
	if (_streamData.capacity() - _streamPosition < Count)
		_streamData.reserve(len);
	if (_streamData.size() < len)
		_streamData.resize(len);

	memcpy(&_streamData[_streamPosition], &Buffer[Offset], Count);
	_streamPosition += Count;
}

void MemoryStream::WriteByte(byte Data)
{
	if (_streamData.size() - _streamPosition < 1)
		_streamData.resize(_streamData.size() + 1);

	memcpy(&_streamData[_streamPosition], &Data, 1);
	_streamPosition += 1;
}

NAMESPACE_IOEND
