#ifndef CEX_CRYPTOKDFEXCEPTION_H
#define CEX_CRYPTOKDFEXCEPTION_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "ExceptionTypes.h"

NAMESPACE_EXCEPTION

using Enumeration::ErrorCodes;
using Enumeration::ExceptionTypes;

/// <summary>
/// Key derivation function exception
/// </summary>
class CryptoKdfException : public CryptoException
{
public:

	/// <summary>
	/// Constructor: instantiate this class with an location, origin, message and error code
	/// </summary>
	///
	/// <param name="Location">The class location of the exception</param>
	/// <param name="Origin">The originating function</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="ErrorCode">The error codes enumeration member</param>
	CryptoKdfException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode);

	/// <summary>
	/// Read Only: The exception class type name
	/// </summary>
	const ExceptionTypes Enumeral();

	/// <summary>
	/// Read: The formal name of this exception type
	/// </summary>
	const std::string Name();
};

NAMESPACE_EXCEPTIONEND
#endif
