#ifndef CEX_CRYPTORANDOMEXCEPTION_H
#define CEX_CRYPTORANDOMEXCEPTION_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "ExceptionTypes.h"

NAMESPACE_EXCEPTION

using Enumeration::ErrorCodes;
using Enumeration::ExceptionTypes;

/// <summary>
/// Cryptographic pseudo random number generator exception
/// </summary>
class CryptoRandomException : public CryptoException
{
public:

	/// <summary>
	/// Constructor: instantiate this class with an origin, message and inner exception
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="Detail">The inner exception string</param>
	/// <param name="ErrorCode">The error code enumeral</param>
	CryptoRandomException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode);

	/// <summary>
	/// Read Only: The exceptions type name
	/// </summary>
	const ExceptionTypes Enumeral();
};

NAMESPACE_EXCEPTIONEND
#endif
