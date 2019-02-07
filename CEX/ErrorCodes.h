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
	/// Invalid symmetric key parameter; information
	/// </summary>
	InvalidInfo = 6,
	/// <summary>
	/// Invalid symmetric key parameter; key
	/// </summary>
	InvalidKey = 7,
	/// <summary>
	/// Invalid symmetric key parameter; nonce
	/// </summary>
	InvalidNonce = 8,
	/// <summary>
	/// Invalid parameter
	/// </summary>
	InvalidParam = 9,
	/// <summary>
	/// Invalid salt parameter
	/// </summary>
	InvalidSalt = 10,
	/// <summary>
	/// Invalid size parameter
	/// </summary>
	InvalidSize = 11,
	/// <summary>
	/// Invalid state
	/// </summary>
	InvalidState = 12,
	/// <summary>
	/// Maximum value exceeded
	/// </summary>
	MaxExceeded = 13,
	/// <summary>
	/// Access was denied
	/// </summary>
	NoAccess = 14,
	/// <summary>
	/// The resource was not found
	/// </summary>
	NotFound = 15,
	/// <summary>
	/// The host could not be found
	/// </summary>
	NoHost = 16,
	/// <summary>
	/// The algorithm was not initialized
	/// </summary>
	NotInitialized = 17,
	/// <summary>
	/// The operation is not supported
	/// </summary>
	NotSupported = 18,
	/// <summary>
	/// The stream is read only
	/// </summary>
	ReadOnly = 19,
	/// <summary>
	/// The number of retries was exceeded
	/// </summary>
	RetriesExceeded = 20,
	/// <summary>
	/// The stream is write only
	/// </summary>
	WriteOnly = 21,
	/// <summary>
	/// The behavior is undefined
	/// </summary>
	UnDefined = 22,
	/// <summary>
	/// An error of unknown origin has occured
	/// </summary>
	UnKnown = 23
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
