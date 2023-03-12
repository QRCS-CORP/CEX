#ifndef CEX_IBYTESTREAM_H
#define CEX_IBYTESTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "SeekOrigin.h"
#include "StreamModes.h"

NAMESPACE_IO

using Exception::CryptoProcessingException;
using Enumeration::StreamModes;

/// <summary>
/// Data stream object interface
/// </summary>
class IByteStream
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IByteStream() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IByteStream() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The stream can be read
	/// </summary>
	virtual const bool CanRead() = 0;

	/// <summary>
	/// Read Only: The stream is seekable
	/// </summary>
	virtual const bool CanSeek() = 0;

	/// <summary>
	/// Read Only: The stream can be written to
	/// </summary>
	virtual const bool CanWrite() = 0;

	/// <summary>
	/// Read Only: The stream container type
	/// </summary>
	virtual const StreamModes Enumeral() = 0;

	/// <summary>
	/// Read Only: The stream length
	/// </summary>
	virtual const uint64_t Length() = 0;

	/// <summary>
	/// Read Only: The streams class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: The streams current position
	/// </summary>
	virtual const uint64_t Position() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Close and flush the stream
	/// </summary>
	virtual void Close() = 0;

	/// <summary>
	/// Copy this stream to another stream
	/// </summary>
	///
	/// <param name="Destination">The destination stream</param>
	virtual void CopyTo(IByteStream* Destination) = 0;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Copies a portion of the stream into an output buffer
	/// </summary>
	///
	/// <param name="Output">The output array receiving the bytes</param>
	/// <param name="Offset">Offset within the output array at which to begin</param>
	/// <param name="Count">The number of bytes to read</param>
	///
	/// <returns>The number of bytes read</returns>
	virtual size_t Read(std::vector<uint8_t> &Output, size_t Offset, size_t Count) = 0;

	/// <summary>
	/// Read a single uint8_t from the stream
	/// </summary>
	///
	/// <returns>The uint8_t value</returns>
	virtual uint8_t ReadByte() = 0;

	/// <summary>
	/// Reset and initialize the underlying digest
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Seek to a position within the stream
	/// </summary>
	/// 
	/// <param name="Offset">The offset position</param>
	/// <param name="Origin">The starting point</param>
	virtual void Seek(uint64_t Offset, SeekOrigin Origin) = 0;

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	virtual void SetLength(uint64_t Length) = 0;

	/// <summary>
	/// Writes an input buffer to the stream
	/// </summary>
	///
	/// <param name="Input">The input array to write to the stream</param>
	/// <param name="Offset">Offset within the input array at which to begin</param>
	/// <param name="Length">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	virtual void Write(const std::vector<uint8_t> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Write a single uint8_t from the stream
	/// </summary>
	///
	/// <param name="Value">The uint8_t value to write</param>
	virtual void WriteByte(uint8_t Value) = 0;
};

NAMESPACE_IOEND
#endif
