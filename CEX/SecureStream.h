#ifndef CEX_SECURESTREAM_H
#define CEX_SECURESTREAM_H

#include "IByteStream.h"

NAMESPACE_IO

/// <summary>
/// A secure memory stream container.
/// <para>Manipulate a uint8_t array through a streaming interface.
/// State is encrypted, and only decrypted during read/write operations.</para>
/// </summary>
class SecureStream final : public IByteStream
{
private:
	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	std::vector<uint8_t> m_keySalt;
	std::vector<uint8_t> m_streamData;
	uint64_t m_streamPosition;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SecureStream(const SecureStream&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SecureStream& operator=(const SecureStream&) = delete;

	/// <summary>
	/// Default constructor: initializes state to zero
	/// </summary>
	SecureStream();

	/// <summary>
	/// Initialize this class and set the streams length
	/// </summary>
	///
	/// <param name="Length">The reserved length of the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(size_t Length, uint64_t KeySalt = 0);

	/// <summary>
	/// Initialize this class with a uint8_t array
	/// </summary>
	///
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(const std::vector<uint8_t> &Data, uint64_t KeySalt = 0);

	/// <summary>
	/// Initialize this class with a uint8_t array with offset and length parameters
	/// </summary>
	/// 
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(std::vector<uint8_t> &Data, size_t Offset, size_t Length, uint64_t KeySalt = 0);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SecureStream() override;

	//~~~Accessors~~~//

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
	/// Read Only: The stream length
	/// </summary>
	const uint64_t Length() override;

	/// <summary>
	/// Read Only: The streams class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The streams current position
	/// </summary>
	const uint64_t Position() override;

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
	size_t Read(std::vector<uint8_t> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Read a single uint8_t from the stream
	/// </summary>
	///
	/// <returns>The uint8_t value</returns>
	uint8_t ReadByte() override;

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
	void Seek(uint64_t Offset, SeekOrigin Origin) override;

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	void SetLength(uint64_t Length) override;

	/// <summary>
	/// Return the underlying uint8_t stream
	/// </summary>
	std::vector<uint8_t> ToArray();

	/// <summary>
	/// Writes an input buffer to the stream
	/// </summary>
	///
	/// <param name="Input">The input array to write to the stream</param>
	/// <param name="Offset">Offset within the input array at which to begin</param>
	/// <param name="Length">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	void Write(const std::vector<uint8_t> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Write a single uint8_t from the stream
	/// </summary>
	///
	/// <param name="Value">The uint8_t value to write</param>
	void WriteByte(uint8_t Value) override;

private:

	std::vector<uint8_t> GetSystemKey();
	void Transform();
};

NAMESPACE_IOEND
#endif
