#include "FileStream.h"
#include "IntUtils.h"

NAMESPACE_IO

void FileStream::Close()
{
	if (_fileStream)
		_fileStream.close();
}

void FileStream::CopyTo(IByteStream* Destination)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileSize == 0)
		throw CryptoProcessingException("FileStream:CopyTo", "The output array is too short!");
#endif

	Destination->Seek(0, CEX::IO::SeekOrigin::Begin);

	if (_fileSize > BLOCK_SIZE)
	{
		size_t aln = _fileSize - (_fileSize % BLOCK_SIZE);
		std::vector<byte> buffer(BLOCK_SIZE);
		_fileStream.seekg(0, std::ios::beg);

		uint ctr = 0;
		do
		{
			_fileStream.read((char*)&buffer, BLOCK_SIZE);
			Destination->Write(buffer, ctr, BLOCK_SIZE);
			ctr += BLOCK_SIZE;

		} while (ctr != aln);

		if (aln != _fileSize)
		{
			_fileStream.read((char*)&buffer, _fileSize - aln);
			Destination->Write(buffer, aln, _fileSize - aln);
		}
	}
	else
	{
		std::vector<byte> buffer(_fileSize);
		_fileStream.seekg(0, std::ios::beg);
		Destination->Write(buffer, 0, _fileSize);
	}
}

void FileStream::Destroy()
{
	if (!m_isDestroyed)
	{
		_filePosition = 0;
		_fileStream.close();
		m_isDestroyed = true;
	}
}

void FileStream::Flush()
{
	if (_fileStream)
		_fileStream.flush();
}

size_t FileStream::Read(std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileAccess == FileAccess::Write)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as write only!");
#endif

	if (Offset + Count > _fileSize - _filePosition)
		Count = _fileSize - _filePosition;

	if (Count > 0)
	{
		// read the data:
		_fileStream.read((char*)&Buffer[Offset], Count);
		_filePosition += Count;
	}

	return Count;
}

byte FileStream::ReadByte()
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileSize - _filePosition < 1)
		throw CryptoProcessingException("FileStream:ReadByte", "The output array is too short!");
	if (_fileAccess == FileAccess::Write)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as write only!");
#endif

	byte data(1);

	_fileStream.read((char*)&data, 1);
	_filePosition += 1;
	return data;
}

void FileStream::Reset()
{
	_fileStream.seekg(0, std::ios::beg);
	_filePosition = 0;
}

void FileStream::Seek(size_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		_fileStream.seekg(Offset, std::ios::beg);
	else if (Origin == SeekOrigin::End)
		_fileStream.seekg(Offset, std::ios::end);
	else
		_fileStream.seekg(Offset, std::ios::cur);

	_filePosition = (uint)_fileStream.tellg();
}

void FileStream::SetLength(size_t Length)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:SetLength", "The file was opened as read only!");
#endif

	_fileStream.seekg(Length - 1, std::ios::beg);
	WriteByte(0);
	_fileStream.seekg(0, std::ios::beg);
}

void FileStream::Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as read only!");
#endif

	_fileStream.write((char*)&Buffer[Offset], Count);
	_filePosition += Count;
	_fileSize += Count;
}

void FileStream::WriteByte(byte Data)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as read only!");
#endif

	_fileStream.write((char*)&Data, 1);
	_filePosition += 1;
	_fileSize += 1;
}

bool FileStream::FileExists(const char* FileName)
{
	try
	{
		std::ifstream infile(FileName);
		bool valid = infile.good();
		infile.close();
		return valid;
	}
	catch (...)
	{
		return false;
	}
}

std::ifstream::pos_type FileStream::FileSize(const char* FileName)
{
	std::ifstream in(FileName, std::ifstream::ate | std::ifstream::binary);
	size_t size = (size_t)in.tellg();
	in.close();
	return size;
}

NAMESPACE_IOEND