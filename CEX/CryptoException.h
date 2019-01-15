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
	std::string m_location;  // Location, Origin, Message, ErrorCode == Class, Function, Message, ErrorCode
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
	/// Constructor: instantiate this class with an origin, message and inner exception
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="Detail">The inner exception string</param>
	/// <param name="ErrorCode">The error code enumeral</param>
	CryptoException(const std::string &Location, const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CryptoException();

	//~~~Accessors~~~//

	/// <summary>
	/// Read: The exception eror code
	/// </summary>
	const ErrorCodes ErrorCode();

	/// <summary>
	/// Read Only: The exceptions type name
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
	/// Read: The origin of the exception in the format Class
	/// </summary>
	const std::string Origin();
};

NAMESPACE_EXCEPTIONEND
#endif
