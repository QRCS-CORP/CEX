#include "FileStream.h"

#if defined(CEX_OS_WINDOWS)
#	include <io.h>  
#	include <fcntl.h>  
#elif defined(CEX_OS_POSIX)
#	include <unistd.h>
#	include <sys/types.h>
#endif

NAMESPACE_IO

//~~~Constructor~~~//

FileStream::FileStream(const std::string &FileName, FileAccess Access, FileModes Mode)
	:
	m_fileAccess(Access),
	m_fileMode(Mode),
	m_fileName(FileName),
	m_isDestroyed(false),
	m_filePosition(0),
	m_fileSize(0),
	m_fileWritten(0)
{
	if (Access == FileAccess::Read && !FileExists(m_fileName))
		throw CryptoProcessingException("FileStream:CTor", "The file does not exist!");

	m_fileSize = FileSize(m_fileName);

	try
	{
		m_fileStream.open(m_fileName, (int)Access | (int)Mode);
		m_fileStream.unsetf(std::ios::skipws);
	}
	catch (std::exception& ex)
	{
		throw CryptoProcessingException("FileStream:CTor", "The file could not be opened!", std::string(ex.what()));
	}
}

FileStream::~FileStream()
{
	Destroy();
}

//~~~Public Functions~~~//

void FileStream::Close()
{
	if (m_fileStream && m_fileStream.is_open())
	{
		if (m_fileWritten != 0)
			m_fileStream.flush();
		m_fileStream.close();
		m_fileSize = 0;
		m_filePosition = 0;
	}
}

void FileStream::CopyTo(IByteStream* Destination)
{
	if (m_fileSize == 0)
		throw CryptoProcessingException("FileStream:CopyTo", "The output array is too short!");

	Destination->Seek(0, IO::SeekOrigin::Begin);

	if (m_fileSize > CHUNK_SIZE)
	{
		size_t aln = m_fileSize - (m_fileSize % CHUNK_SIZE);
		std::vector<byte> buffer(CHUNK_SIZE);
		m_fileStream.seekg(0, std::ios::beg);

		uint ctr = 0;
		do
		{
			m_fileStream.read((char*)&buffer, CHUNK_SIZE);
			Destination->Write(buffer, ctr, CHUNK_SIZE);
			ctr += CHUNK_SIZE;

		} while (ctr != aln);

		if (aln != m_fileSize)
		{
			m_fileStream.read((char*)&buffer, m_fileSize - aln);
			Destination->Write(buffer, aln, m_fileSize - aln);
		}
	}
	else
	{
		std::vector<byte> buffer(m_fileSize);
		m_fileStream.seekg(0, std::ios::beg);
		Destination->Write(buffer, 0, m_fileSize);
	}
}

void FileStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_filePosition = 0;
		Close();
		m_isDestroyed = true;
	}
}

bool FileStream::FileExists(const std::string &FileName)
{
	std::ifstream infile(FileName.c_str());
	return infile.good();
}

uint64_t FileStream::FileSize(const std::string &FileName)
{
	if (!FileExists(FileName))
		return 0;

	std::ifstream in(FileName.c_str(), std::ifstream::ate | std::ifstream::binary);
	return static_cast<uint64_t>(in.tellg());
}

void FileStream::Flush()
{
	if (m_fileStream && m_fileWritten != 0)
		m_fileStream.flush();
}

size_t FileStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (m_fileAccess == FileAccess::Write)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as write only!");

	if (Offset + Length > m_fileSize - m_filePosition)
		Length = m_fileSize - m_filePosition;

	if (Length > 0)
	{
		// read the data:
		m_fileStream.read((char*)&Output[Offset], Length);
		m_filePosition += Length;
	}

	return Length;
}

byte FileStream::ReadByte()
{
	if (m_fileSize - m_filePosition < 1)
		throw CryptoProcessingException("FileStream:ReadByte", "The output array is too short!");
	if (m_fileAccess == FileAccess::Write)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as write only!");

	byte data(1);

	m_fileStream.read((char*)&data, 1);
	m_filePosition += 1;
	return data;
}

void FileStream::Reset()
{
	m_fileStream.seekg(0, std::ios::beg);
	m_filePosition = 0;
}

void FileStream::Seek(uint64_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		m_fileStream.seekg(Offset, std::ios::beg);
	else if (Origin == SeekOrigin::End)
		m_fileStream.seekg(Offset, std::ios::end);
	else
		m_fileStream.seekg(Offset, std::ios::cur);

	m_filePosition = static_cast<uint64_t>(m_fileStream.tellg());
}

void FileStream::SetLength(uint64_t Length)
{
	if (m_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:SetLength", "The file was opened as read only!");

	if (Length < m_fileSize)
	{
#if defined(CEX_OS_WINDOWS)

		int handle;
		if (_sopen_s(&handle, m_fileName.c_str(), _O_RDWR | _O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE) == 0)
			_chsize(handle, Length);

#elif defined(CEX_OS_POSIX)

		truncate(m_fileName.c_str(), Length);

#endif
	}
	else if (Length > m_fileSize)
	{
		m_fileStream.seekg(Length - 1, std::ios::beg);
		m_fileStream.write("", 1);
		m_fileStream.seekg(0, std::ios::beg);
	}
}

void FileStream::Write(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (m_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as read only!");

	m_fileStream.write((char*)&Input[Offset], Length);
	m_filePosition += Length;
	m_fileSize += Length;
	m_fileWritten += Length;

	if (m_fileWritten >= CHUNK_SIZE)
	{
		m_fileStream.flush();
		m_fileWritten = 0;
	}
}

void FileStream::WriteByte(byte Value)
{
	if (m_fileAccess == FileAccess::Read)
		throw CryptoProcessingException("FileStream:Write", "The file was opened as read only!");

	m_fileStream.write((char*)&Value, 1);
	m_filePosition++;
	m_fileSize++;
	m_fileWritten++;

	if (m_fileWritten >= CHUNK_SIZE)
	{
		m_fileStream.flush();
		m_fileWritten = 0;
	}
}

NAMESPACE_IOEND