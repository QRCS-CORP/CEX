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
	None = 0x00,
	/// <summary>
	/// The operation was successful
	/// </summary>
	Success = 0x01,
	/// <summary>
	/// Authorization failure
	/// </summary>
	AuthFail = 0x02,
	/// <summary>
	/// Stream can not be read
	/// </summary>
	BadRead = 0x03,
	/// <summary>
	/// The pipe was disconnected
	/// </summary>
	Disconnected = 0x04,
	/// <summary>
	/// Invalid key
	/// </summary>
	InvalidKey = 0x05,
	/// <summary>
	/// Invalid parameter
	/// </summary>
	InvalidParam = 0x06,
	/// <summary>
	/// Invalid size parameter
	/// </summary>
	InvalidSize = 0x07,
	/// <summary>
	/// Maximum value exceeded
	/// </summary>
	MaxExceeded = 0x08,
	/// <summary>
	/// Access was denied
	/// </summary>
	NoAccess = 0x09,
	/// <summary>
	/// The resource was not found
	/// </summary>
	NotFound = 0x0A,
	/// <summary>
	/// The host could not be found
	/// </summary>
	NoHost = 0x0B,
	/// <summary>
	/// The algorithm was not initialized
	/// </summary>
	NotInitialized = 0x0C,
	/// <summary>
	/// The operation is not supported
	/// </summary>
	NotSupported = 0x0D,
	/// <summary>
	/// The stream is read only
	/// </summary>
	ReadOnly = 0x0E,
	/// <summary>
	/// The number of retries was exceeded
	/// </summary>
	RetriesExceeded = 0x0F,
	/// <summary>
	/// The stream is write only
	/// </summary>
	WriteOnly = 0x10,
	/// <summary>
	/// The behavior is undefined
	/// </summary>
	UnDefined = 0x11,
	/// <summary>
	/// An error of unknown origin has occured
	/// </summary>
	UnKnown = 0x12
};

NAMESPACE_ENUMERATIONEND
#endif
