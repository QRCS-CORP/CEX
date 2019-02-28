#ifndef CEX_CRYPTOEXCEPTION_H
#define CEX_CRYPTOEXCEPTION_H

#include "CexDomain.h"
#include "ErrorCodes.h"
#include "ExceptionTypes.h"

NAMESPACE_EXCEPTION

using Enumeration::ErrorCodes;
using Enumeration::ExceptionTypes;

/// <summary>
/// Base cryptographic exception container.
/// <para>All of the CEX library errors can be caught using this base class.</para>
/// </summary>
class CryptoException : public std::exception
{
private:

	ErrorCodes m_error;
	std::string m_location;
	std::string m_message;
	std::string m_origin;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CryptoException& operator=(const CryptoException&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CryptoException() = delete;

	/// <summary>
	/// Constructor: instantiate this class with an location, origin, message and error code
	/// </summary>
	///
	/// <param name="Location">The class location of the exception</param>
	/// <param name="Origin">The originating function</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="ErrorCode">The error codes enumeration member</param>
	CryptoException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CryptoException();

	//~~~Accessors~~~//

	/// <summary>
	/// Read: The exception error code
	/// </summary>
	const ErrorCodes ErrorCode();

	/// <summary>
	/// Read Only: The exception class type name
	/// </summary>
	const ExceptionTypes Enumeral();

	/// <summary>
	/// Read: The class location string
	/// </summary>
	const std::string Location();

	/// <summary>
	/// Read: The message associated with the error
	/// </summary>
	const std::string Message();

	/// <summary>
	/// Read: The formal name of this exception type
	/// </summary>
	const std::string Name();

	/// <summary>
	/// Read: The origin of the exception in the format Class
	/// </summary>
	const std::string Origin();
};

NAMESPACE_EXCEPTIONEND
#endif
