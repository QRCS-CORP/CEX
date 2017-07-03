#ifndef _CEX_SECURESTREAM_H
#define _CEX_SECURESTREAM_H

#include "IByteStream.h"

NAMESPACE_IO

/// <summary>
/// A secure memory stream container.
/// <para>Manipulate a byte array through a streaming interface.
/// State is encrypted, and only decrypted during read/write operations.</para>
/// </summary>
class SecureStream : public IByteStream
{
private:
	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	std::vector<byte> m_keySalt;
	std::vector<byte> m_streamData;
	ulong m_streamPosition;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The stream can be read
	/// </summary>
	const bool CanRead() override;

	/// <summary>
	/// Get: The stream is seekable
	/// </summary>
	const bool CanSeek() override;

	/// <summary>
	/// Get: The stream can be written to
	/// </summary>
	const bool CanWrite() override;

	/// <summary>
	/// Get: The stream container type
	/// </summary>
	const StreamModes Enumeral() override;

	/// <summary>
	/// Get: The stream length
	/// </summary>
	const ulong Length() override;

	/// <summary>
	/// Get: The streams class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	const ulong Position() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize and empty stream
	/// </summary>
	SecureStream();

	/// <summary>
	/// Initialize this class and set the streams length
	/// </summary>
	///
	/// <param name="Length">The reserved length of the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(size_t Length, ulong KeySalt = 0);

	/// <summary>
	/// Initialize this class with a byte array
	/// </summary>
	///
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(const std::vector<byte> &Data, ulong KeySalt = 0);

	/// <summary>
	/// Initialize this class with a byte array with offset and length parameters
	/// </summary>
	/// 
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(std::vector<byte> &Data, size_t Offset, size_t Length, ulong KeySalt = 0);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~SecureStream() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Close and flush the stream (not used in SecureStream)
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
	/// Copies a portion of the stream into an output buffer
	/// </summary>
	///
	/// <param name="Output">The output array receiving the bytes</param>
	/// <param name="Offset">Offset within the output array at which to begin</param>
	/// <param name="Length">The number of bytes to read</param>
	///
	/// <returns>The number of bytes processed</returns>
	size_t Read(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
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
	/// Return the underlying byte stream
	/// </summary>
	std::vector<byte> ToArray();

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

private:

	std::vector<byte> GetSystemKey();
	void Transform();
};

NAMESPACE_IOEND
#endif