#ifndef CEX_ERRORCODES_H
#define CEX_ERRORCODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// A list of library error codes
/// </summary>
enum class ErrorCodes : uint8_t
{
	/// <summary>
	/// No error code was specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The operation was successful
	/// </summary>
	Success = 1,
	/// <summary>
	/// Authorization failure
	/// </summary>
	AuthenticationFailure = 2,
	/// <summary>
	/// Stream can not be read
	/// </summary>
	BadRead = 3,
	/// <summary>
	/// The pipe was disconnected
	/// </summary>
	Disconnected = 4,
	/// <summary>
	/// Illegal operation request
	/// </summary>
	IllegalOperation = 5,
	/// <summary>
	/// The IP address is invalid
	/// </summary>
	InvalidAddress = 6,
	/// <summary>
	/// Invalid symmetric key parameter; information
	/// </summary>
	InvalidInfo = 7,
	/// <summary>
	/// Invalid symmetric key parameter; key
	/// </summary>
	InvalidKey = 8,
	/// <summary>
	/// Invalid symmetric key parameter; nonce
	/// </summary>
	InvalidNonce = 9,
	/// <summary>
	/// Invalid parameter
	/// </summary>
	InvalidParam = 10,
	/// <summary>
	/// Invalid salt parameter
	/// </summary>
	InvalidSalt = 11,
	/// <summary>
	/// Invalid size parameter
	/// </summary>
	InvalidSize = 12,
	/// <summary>
	/// Invalid state
	/// </summary>
	InvalidState = 13,
	/// <summary>
	/// Maximum value exceeded
	/// </summary>
	MaxExceeded = 14,
	/// <summary>
	/// Access was denied
	/// </summary>
	NoAccess = 15,
	/// <summary>
	/// The resource was not found
	/// </summary>
	NotFound = 16,
	/// <summary>
	/// The host could not be found
	/// </summary>
	NoHost = 17,
	/// <summary>
	/// The algorithm was not initialized
	/// </summary>
	NotInitialized = 18,
	/// <summary>
	/// The operation is not supported
	/// </summary>
	NotSupported = 19,
	/// <summary>
	/// The stream is read only
	/// </summary>
	ReadOnly = 20,
	/// <summary>
	/// The number of retries was exceeded
	/// </summary>
	RetriesExceeded = 21,
	/// <summary>
	/// The socket was unexpectedly disconnected
	/// </summary>
	SocketDisconnected = 22,
	/// <summary>
	/// The socket operation experienced and unrecoverable error
	/// </summary>
	SocketError = 23,
	/// <summary>
	/// The socket operation has failed
	/// </summary>
	SocketFailure = 24,
	/// <summary> 
	/// The socket parameters are invalid
	/// </summary>
	SocketInvalid = 25,
	/// <summary>
	/// The socket operation was refused
	/// </summary>
	SocketRefused = 26,
	/// <summary>
	/// The socket destination is unreachable
	/// </summary>
	SocketUnreachable = 27,
	/// <summary>
	/// The destination host is unreachable
	/// </summary>
	Unreachable = 28,
	/// <summary>
	/// The stream is write only
	/// </summary>
	WriteOnly = 29,
	/// <summary>
	/// The behavior is undefined
	/// </summary>
	UnDefined = 30,
	/// <summary>
	/// An error of unknown origin has occured
	/// </summary>
	UnKnown = 254
};

class ErrorCodeConvert
{
public:

	/// <summary>
	/// Get the brief description for a type of error code
	/// </summary>
	/// 
	/// <param name="Enumeral">The ErrorCode enumeration member</param>
	///
	/// <returns>The error types description string</returns>
	static std::string Description(ErrorCodes Enumeral);
};

NAMESPACE_ENUMERATIONEND
#endif
