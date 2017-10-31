#ifndef CEX_FILESTREAM_H
#define CEX_FILESTREAM_H

#include "IByteStream.h"
#include <fstream>
#include <iostream>

NAMESPACE_IO

/// <summary>
/// A file streaming container.
/// <para>Manipulate a file through a streaming interface.</para>
/// </summary>
class FileStream final : public IByteStream
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

	static const uint CHUNK_SIZE = 4096;
	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	std::string m_fileName;
	ulong m_filePosition;
	ulong m_fileSize;
	ulong m_fileWritten;
	std::fstream m_fileStream;
	FileAccess m_fileAccess;
	FileModes m_fileMode;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	FileStream(const FileStream&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	FileStream& operator=(const FileStream&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	FileStream() = delete;

	/// <summary>
	/// Constructor: instantiate this class with a file name and options
	/// </summary>
	///
	/// <param name="FileName">The full path and name of the file</param>
	/// <param name="Access">The level of access requested</param>
	/// <param name="Mode">The file processing mode</param>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the file could not be opened</exception>
	explicit FileStream(const std::string &FileName, FileAccess Access = FileAccess::ReadWrite, FileModes Mode = FileModes::Binary);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~FileStream() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The file read and write file access flags
	/// </summary>
	const FileAccess Access();

	/// <summary>
	/// Read Only: The stream can be read
	/// </summary>
	const bool CanRead() override;

	/// <summary>
	/// Read Only: The stream is seekable
	/// </summary>
	const bool CanSeek() override;

	/// <summary>
	/// Read Only: The stream can be written to
	/// </summary>
	const bool CanWrite() override;

	/// <summary>
	/// Read Only: The stream container type
	/// </summary>
	const StreamModes Enumeral() override;

	/// <summary>
	/// Read Only: The file open mode flags
	/// </summary>
	const FileModes FileMode();

	/// <summary>
	/// Read Only: The file name and path
	/// </summary>
	std::string FileName();

	/// <summary>
	/// Read Only: The stream length
	/// </summary>
	const ulong Length() override;

	/// <summary>
	/// Read Only: The streams class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The streams current position
	/// </summary>
	const ulong Position() override;

	/// <summary>
	/// Read/Write: The underlying stream
	/// </summary>
	std::fstream &Stream();

	//~~~Public Functions~~~//

	/// <summary>
	/// Close and flush the stream
	/// </summary>
	void Close() override;

	/// <summary>
	/// Copy this stream to another stream
	/// </summary>
	///
	/// <param name="Destination">The destination stream</param>
	void CopyTo(IByteStream* Destination) override;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

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
	size_t Read(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The read byte value</returns>
	byte ReadByte() override;

	/// <summary>
	/// Reset and initialize the underlying stream to zero
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Seek to a position within the stream
	/// </summary>
	/// 
	/// <param name="Offset">The offset position</param>
	/// <param name="Origin">The starting point</param>
	void Seek(ulong Offset, SeekOrigin Origin) override;

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	void SetLength(ulong Length) override;

	/// <summary>
	/// Writes an input buffer to the stream
	/// </summary>
	///
	/// <param name="Input">The input array to write to the stream</param>
	/// <param name="Offset">Offset within the input array at which to begin</param>
	/// <param name="Length">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	void Write(const std::vector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <param name="Value">The byte value to write</param>
	void WriteByte(byte Value) override;
};

NAMESPACE_IOEND
#endif