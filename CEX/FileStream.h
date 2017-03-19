#ifndef _CEX_FILESTREAM_H
#define _CEX_FILESTREAM_H

#include "IByteStream.h"
#include <fstream>
#include <iostream>

NAMESPACE_IO

/// <summary>
/// A file streaming container.
/// <para>Manipulate a file through a streaming interface.</para>
/// </summary>
class FileStream : public IByteStream
{
public:

	//~~~Enums~~~//

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
	enum class FileModes : int
	{
		Append = std::ios::app,
		AtEnd = std::ios::ate,
		Binary = std::ios::binary,
		Truncate = std::ios::trunc
	};

private:

	const uint CHUNK_SIZE = 4096;
	bool m_isDestroyed;
	std::string m_fileName;
	ulong m_filePosition;
	ulong m_fileSize;
	ulong m_fileWritten;
	std::fstream m_fileStream;
	FileAccess m_fileAccess;
	FileModes m_fileMode;

public:

	FileStream() = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The file read and write file access flags
	/// </summary>
	const FileAccess Access() { return m_fileAccess; }

	/// <summary>
	/// Get: The stream can be read
	/// </summary>
	virtual const bool CanRead() { return m_fileAccess != FileAccess::Write; }

	/// <summary>
	/// Get: The stream is seekable
	/// </summary>
	virtual const bool CanSeek() { return true; }

	/// <summary>
	/// Get: The stream can be written to
	/// </summary>
	virtual const bool CanWrite() { return m_fileAccess != FileAccess::Read; }

	/// <summary>
	/// Get: The stream container type
	/// </summary>
	virtual const StreamModes Enumeral() { return StreamModes::FileStream; }

	/// <summary>
	/// Get: The file open mode flags
	/// </summary>
	const FileModes FileMode() { return m_fileMode; }

	/// <summary>
	/// Get: The file name and path
	/// </summary>
	std::string FileName() { return m_fileName; }

	/// <summary>
	/// Get: The stream length
	/// </summary>
	virtual const ulong Length() { return m_fileSize; }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const ulong Position() { return m_filePosition; }

	/// <summary>
	/// Get: The underlying stream
	/// </summary>
	std::fstream &Stream() { return m_fileStream; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class with a file name and options
	/// </summary>
	///
	/// <param name="FileName">The full path and name of the file</param>
	/// <param name="Access">The level of access requested</param>
	/// <param name="Mode">The file processing mode</param>
	explicit FileStream(const std::string &FileName, FileAccess Access = FileAccess::ReadWrite, FileModes Mode = FileModes::Binary);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~FileStream();

	//~~~Public Functions~~~//

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
	/// Check if a file exists
	/// </summary>
	///
	/// <param name="FileName">The full path and file name</param>
	///
	/// <returns>Returns true if the file exists</returns>
	static bool FileExists(const std::string &FileName);

	/// <summary>
	/// Get the file size in bytes
	/// </summary>
	///
	/// <param name="FileName">The full path and file name</param>
	///
	/// <returns>Returns the file size</returns>
	static ulong FileSize(const std::string &FileName);

	/// <summary>
	/// Write the stream to disk
	/// </summary>
	void Flush();

	/// <summary>
	/// Copies a portion of the stream into an output buffer
	/// </summary>
	///
	/// <param name="Output">The output array receiving the bytes</param>
	/// <param name="Offset">Offset within the output array at which to begin</param>
	/// <param name="Length">The number of bytes to read</param>
	///
	/// <returns>The number of bytes read</returns>
	virtual size_t Read(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The read byte value</returns>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the stream is too short or the file is write only</exception>
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
	virtual void Seek(ulong Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void SetLength(ulong Length);

	/// <summary>
	/// Writes an input buffer to the stream
	/// </summary>
	///
	/// <param name="Input">The input array to write to the stream</param>
	/// <param name="Offset">Offset within the input array at which to begin</param>
	/// <param name="Length">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void Write(const std::vector<byte> &Input, size_t Offset, size_t Length);

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <param name="Value">The byte value to write</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the file is read only</exception>
	virtual void WriteByte(byte Value);
};

NAMESPACE_IOEND
#endif