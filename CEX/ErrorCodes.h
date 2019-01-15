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
	/// Invalid key
	/// </summary>
	InvalidKey = 6,
	/// <summary>
	/// Invalid parameter
	/// </summary>
	InvalidParam = 7,
	/// <summary>
	/// Invalid size parameter
	/// </summary>
	InvalidSize = 8,
	/// <summary>
	/// Invalid state
	/// </summary>
	InvalidState = 9,
	/// <summary>
	/// Maximum value exceeded
	/// </summary>
	MaxExceeded = 10,
	/// <summary>
	/// Access was denied
	/// </summary>
	NoAccess = 11,
	/// <summary>
	/// The resource was not found
	/// </summary>
	NotFound = 12,
	/// <summary>
	/// The host could not be found
	/// </summary>
	NoHost = 13,
	/// <summary>
	/// The algorithm was not initialized
	/// </summary>
	NotInitialized = 14,
	/// <summary>
	/// The operation is not supported
	/// </summary>
	NotSupported = 15,
	/// <summary>
	/// The stream is read only
	/// </summary>
	ReadOnly = 16,
	/// <summary>
	/// The number of retries was exceeded
	/// </summary>
	RetriesExceeded = 17,
	/// <summary>
	/// The stream is write only
	/// </summary>
	WriteOnly = 18,
	/// <summary>
	/// The behavior is undefined
	/// </summary>
	UnDefined = 19,
	/// <summary>
	/// An error of unknown origin has occured
	/// </summary>
	UnKnown = 20
};

NAMESPACE_ENUMERATIONEND
#endif
