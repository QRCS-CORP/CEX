#include "FileStream.h"

#if defined(CEX_OS_WINDOWS)
#	include <io.h>  
#	include <fcntl.h>  
#elif defined(CEX_OS_POSIX)
#	include <unistd.h>
#	include <sys/types.h>
#endif

NAMESPACE_IO

const std::string FileStream::CLASS_NAME("FileStream");

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
	{
		throw CryptoProcessingException("FileStream:CTor", "The file does not exist!");
	}

	m_fileSize = FileSize(m_fileName);

	try
	{
		m_fileStream.open(m_fileName, static_cast<int>(Access) | static_cast<int>(Mode));
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

//~~~Accessors~~~//

const FileStream::FileAccess FileStream::Access() 
{ 
	return m_fileAccess; 
}

const bool FileStream::CanRead() 
{ 
	return m_fileAccess != FileAccess::Write; 
}

const bool FileStream::CanSeek()
{
	return true; 
}

const bool FileStream::CanWrite() 
{
	return m_fileAccess != FileAccess::Read; 
}

const StreamModes FileStream::Enumeral() 
{
	return StreamModes::FileStream;
}

const FileStream::FileModes FileStream::FileMode() 
{ 
	return m_fileMode;
}

std::string FileStream::FileName() 
{ 
	return m_fileName; 
}

const ulong FileStream::Length() 
{ 
	return m_fileSize;
}

const std::string FileStream::Name()
{
	return CLASS_NAME;
}

const ulong FileStream::Position()
{ 
	return m_filePosition;
}

std::fstream &FileStream::Stream() 
{
	return m_fileStream; 
}

//~~~Public Functions~~~//

void FileStream::Close()
{
	if (m_fileStream && m_fileStream.is_open())
	{
		if (m_fileWritten != 0)
		{
			m_fileStream.flush();
		}

		m_fileStream.close();
		m_fileSize = 0;
		m_filePosition = 0;
	}
}

void FileStream::CopyTo(IByteStream* Destination)
{
	CexAssert(m_fileSize != 0, "stream is too short");

	Destination->Seek(0, IO::SeekOrigin::Begin);

	if (m_fileSize > CHUNK_SIZE)
	{
		const size_t ALNSZE = m_fileSize - (m_fileSize % CHUNK_SIZE);
		std::vector<byte> buffer(CHUNK_SIZE);
		m_fileStream.seekg(0, std::ios::beg);

		uint bteCtr = 0;

		if (ALNSZE >= CHUNK_SIZE)
		{
			while (bteCtr != ALNSZE)
			{
				m_fileStream.read((char*)buffer.data(), CHUNK_SIZE);
				Destination->Write(buffer, bteCtr, CHUNK_SIZE);
				bteCtr += CHUNK_SIZE;
			}
		}

		if (ALNSZE != m_fileSize)
		{
			m_fileStream.read((char*)buffer.data(), m_fileSize - ALNSZE);
			Destination->Write(buffer, ALNSZE, m_fileSize - ALNSZE);
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
		m_isDestroyed = true;
		m_filePosition = 0;
		Close();
	}
}

bool FileStream::FileExists(const std::string &FileName)
{
	std::ifstream infile(FileName.c_str());
	return infile.good();
}

ulong FileStream::FileSize(const std::string &FileName)
{
	if (!FileExists(FileName))
	{
		return 0;
	}

	std::ifstream in(FileName.c_str(), std::ifstream::ate | std::ifstream::binary);
	return static_cast<ulong>(in.tellg());
}

void FileStream::Flush()
{
	CexAssert(m_fileAccess != FileAccess::Read, "File is read only");

	if (m_fileStream && m_fileWritten != 0)
	{
		m_fileStream.flush();
	}
}

size_t FileStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(m_fileAccess != FileAccess::Write, "File is write only");

	if (Offset + Length > m_fileSize - m_filePosition)
	{
		Length = m_fileSize - m_filePosition;
	}

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
	CexAssert(m_fileSize - m_filePosition >= 1, "Reached end of file");
	CexAssert(m_fileAccess != FileAccess::Write, "File is write only");

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

void FileStream::Seek(ulong Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
	{
		m_fileStream.seekg(Offset, std::ios::beg);
	}
	else if (Origin == SeekOrigin::End)
	{
		m_fileStream.seekg(Offset, std::ios::end);
	}
	else
	{
		m_fileStream.seekg(Offset, std::ios::cur);
	}

	m_filePosition = static_cast<ulong>(m_fileStream.tellg());
}

void FileStream::SetLength(ulong Length)
{
	CexAssert(m_fileAccess != FileAccess::Read, "File is read only");

	if (Length < m_fileSize)
	{
#if defined(CEX_OS_WINDOWS)
		int handle = 0;

		if (_sopen_s(&handle, m_fileName.c_str(), _O_RDWR | _O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE) == 0)
		{
			_chsize(handle, Length);
		}
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
	CexAssert(m_fileAccess != FileAccess::Read, "File is read only");

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
	CexAssert(m_fileAccess != FileAccess::Read, "File is read only");

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
