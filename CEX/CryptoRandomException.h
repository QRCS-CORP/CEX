#ifndef CEX_CRYPTORANDOMEXCEPTION_H
#define CEX_CRYPTORANDOMEXCEPTION_H

#include "CexDomain.h"
#include "ErrorCodes.h"

NAMESPACE_EXCEPTION

using Enumeration::ErrorCodes;

/// <summary>
/// Wraps exceptions thrown within Pseudo Random Number Generator operations
/// </summary>
struct CryptoRandomException : std::exception
{
private:

	std::string m_details;
	ErrorCodes m_error;
	std::string m_message;
	std::string m_origin;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CryptoRandomException& operator=(const CryptoRandomException&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CryptoRandomException() = delete;

	/// <summary>
	/// Constructor: instantiate this class with a message
	/// </summary>
	///
	/// <param name="Message">A custom message or error data</param>
	explicit CryptoRandomException(const std::string &Message);

	/// <summary>
	/// Constructor: instantiate this class with an origin and message
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	CryptoRandomException(const std::string &Origin, const std::string &Message);

	/// <summary>
	/// Constructor: instantiate this class with an origin and message
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="ErrorCode">The error code enumeral</param>
	CryptoRandomException(const std::string &Origin, const std::string &Message, ErrorCodes ErrorCode);

	/// <summary>
	/// Constructor: instantiate this class with an origin, message and inner exception
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="Detail">The inner exception string</param>
	CryptoRandomException(const std::string &Origin, const std::string &Message, const std::string &Detail);

	/// <summary>
	/// Constructor: instantiate this class with an origin, message and inner exception
	/// </summary>
	///
	/// <param name="Origin">The origin of the exception</param>
	/// <param name="Message">A custom message or error data</param>
	/// <param name="Detail">The inner exception string</param>
	/// <param name="ErrorCode">The error code enumeral</param>
	CryptoRandomException(const std::string &Origin, const std::string &Message, const std::string &Detail, ErrorCodes ErrorCode);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CryptoRandomException();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The inner exception string
	/// </summary>
	std::string &Details();

	/// <summary>
	/// Read/Write: The exception eror code
	/// </summary>
	ErrorCodes &ErrorCode();

	/// <summary>
	/// Read/Write: The message associated with the error
	/// </summary>
	std::string &Message();

	/// <summary>
	/// Read/Write: The origin of the exception in the format Class
	/// </summary>
	std::string &Origin();
};

NAMESPACE_EXCEPTIONEND
#endif
