#ifndef _CEXENGINE_FILESTREAM_H
#define _CEXENGINE_FILESTREAM_H

#include "IByteStream.h"
#include <iostream>
#include <fstream>

NAMESPACE_IO

/// <summary>
/// Write data values to a file
/// </summary>
class FileStream : public IByteStream
{
public:
	/// <summary>
	/// File access type flags
	/// </summary>
	enum class FileAccess : int
	{
		Read = std::ios::in,
		ReadWrite = std::ios::out | std::ios::in,
		Write = std::ios::out
	};

	/// <summary>
	/// File operation mode flags
	/// </summary>
	enum class FileMode : int
	{
		Append = std::ios::app,
		AtEnd = std::ios::ate,
		Binary = std::ios::binary,
		Truncate = std::ios::trunc
	};

private:
	static constexpr uint BLOCK_SIZE = 4096;

	bool m_isDestroyed;
	const char* _filename;
	size_t _filePosition;
	size_t _fileSize;
	std::fstream _fileStream;
	FileAccess _fileAccess;
	FileMode _fileMode;

	FileStream() {}

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The stream can be read
	/// </summary>
	virtual const bool CanRead() { return _fileAccess != FileAccess::Write; }

	/// <summary>
	/// Get: The stream is seekable
	/// </summary>
	virtual const bool CanSeek() { return true; }

	/// <summary>
	/// Get: The stream can be written to
	/// </summary>
	virtual const bool CanWrite() { return _fileAccess != FileAccess::Read; }

	/// <summary>
	/// Get: The stream length
	/// </summary>
	virtual const size_t Length() { return _fileSize; }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const size_t Position() { return _filePosition; }

	/// <summary>
	/// Get: The underlying stream
	/// </summary>
	std::fstream &Stream() { return _fileStream; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	///
	/// <param name="FileName">The full path to the file</param>
	/// <param name="Access">The level of access requested</param>
	/// <param name="Mode">The file processing mode</param>
	explicit FileStream(const std::string &FileName, FileAccess Access = FileAccess::ReadWrite, FileMode Mode = FileMode::Binary)
		:
		_fileAccess(Access),
		_fileMode(Mode),
		_filename(0),
		m_isDestroyed(false),
		_filePosition(0),
		_fileSize(0)
	{
		_filename = FileName.c_str();

		if (Access == FileAccess::Read && !FileExists(_filename))
			throw CryptoProcessingException("FileStream:CTor", "The file does not exist!");

		_fileSize = (size_t)FileSize(_filename);

		try
		{
			_fileStream.open(_filename, (int)Access | (int)Mode);
			_fileStream.unsetf(std::ios::skipws);
		}
		catch (...)
		{
			throw CryptoProcessingException("FileStream:CTor", "The file could not be opened!");
		}
	}

	// *** Public Methods *** //

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~FileStream()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Close and flush the stream
	/// </summary>
	virtual void Close();

	/// <summary>
	/// Copy this stream to another stream
	/// </summary>
	///
	/// <param name="Destination">The destination stream</param>
	virtual void CopyTo(IByteStream* Destination);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Write the stream to disk
	/// </summary>
	virtual void Flush();

	/// <summary>
	/// Reads a portion of the stream into the buffer
	/// </summary>
	///
	/// <param name="Buffer">The output buffer receiving the bytes</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to read</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t Read(std::vector<byte> &Buffer, size_t Offset, size_t Count);

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the stream is too short or the file is write only</exception>
	virtual byte ReadByte();

	/// <summary>
	/// Reset and initialize the underlying stream to zero
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Seek to a position within the stream
	/// </summary>
	/// 
	/// <param name="Offset">The offset position</param>
	/// <param name="Origin">The starting point</param>
	virtual void Seek(size_t Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void SetLength(size_t Length);

	/// <summary>
	/// Writes a buffer into the stream
	/// </summary>
	///
	/// <param name="Buffer">The output buffer to write to the stream</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to write</param>
	///
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count);

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void WriteByte(byte Data);

private:
	bool FileExists(const char* FileName);

	std::ifstream::pos_type FileSize(const char* FileName);
};

NAMESPACE_IOEND
#endif