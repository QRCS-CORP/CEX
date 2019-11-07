#ifndef CEX_ERRORCODES_H
#define CEX_ERRORCODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// A list of library error codes
/// </summary>
enum class ErrorCodes : byte
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
	/// The socket parameters are invalid
	/// </summary>
	InvalidSocket = 13,
	/// <summary>
	/// Invalid state
	/// </summary>
	InvalidState = 14,
	/// <summary>
	/// Maximum value exceeded
	/// </summary>
	MaxExceeded = 15,
	/// <summary>
	/// Access was denied
	/// </summary>
	NoAccess = 16,
	/// <summary>
	/// The resource was not found
	/// </summary>
	NotFound = 17,
	/// <summary>
	/// The host could not be found
	/// </summary>
	NoHost = 18,
	/// <summary>
	/// The algorithm was not initialized
	/// </summary>
	NotInitialized = 19,
	/// <summary>
	/// The operation is not supported
	/// </summary>
	NotSupported = 20,
	/// <summary>
	/// The stream is read only
	/// </summary>
	ReadOnly = 21,
	/// <summary>
	/// The number of retries was exceeded
	/// </summary>
	RetriesExceeded = 22,
	/// <summary>
	/// The socket operation has failed
	/// </summary>
	SocketFailure = 23,
	/// <summary>
	/// The destination host is unreachable
	/// </summary>
	Unreachable = 24,
	/// <summary>
	/// The stream is write only
	/// </summary>
	WriteOnly = 25,
	/// <summary>
	/// The behavior is undefined
	/// </summary>
	UnDefined = 26,
	/// <summary>
	/// An error of unknown origin has occured
	/// </summary>
	UnKnown = 27
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
