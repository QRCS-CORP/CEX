#include "ErrorCodes.h"

NAMESPACE_ENUMERATION

std::string ErrorCodeConvert::Description(ErrorCodes Enumeral)
{
	std::string name("");

	switch (Enumeral)
	{
	case ErrorCodes::None:
		name = std::string("No error code was specified");
		break;
	case ErrorCodes::Success:
		name = std::string("The previous operation was successful");
		break;
	case ErrorCodes::AuthenticationFailure:
		name = std::string("An authentication operation has failed");
		break;
	case ErrorCodes::BadRead:
		name = std::string("The stream can not be read");
		break;
	case ErrorCodes::Disconnected:
		name = std::string("The pipe was disconnected");
		break;
	case ErrorCodes::IllegalOperation:
		name = std::string("Illegal operation requested");
		break;
	case ErrorCodes::InvalidInfo:
		name = std::string("Invalid symmetric key parameter; information");
		break;
	case ErrorCodes::InvalidKey:
		name = std::string("Invalid symmetric key parameter; key");
		break;
	case ErrorCodes::InvalidNonce:
		name = std::string("Invalid symmetric key parameter; nonce");
		break;
	case ErrorCodes::InvalidParam:
		name = std::string("Invalid function parameter");
		break;
	case ErrorCodes::InvalidSalt:
		name = std::string("Invalid salt parameter");
		break;
	case ErrorCodes::InvalidSize:
		name = std::string("Invalid size parameter");
		break;
	case ErrorCodes::InvalidState:
		name = std::string("The internal state is invalid");
		break;
	case ErrorCodes::MaxExceeded:
		name = std::string("Maximum allowed value was exceeded");
		break;
	case ErrorCodes::NoAccess:
		name = std::string("Access to the resource was denied");
		break;
	case ErrorCodes::NotFound:
		name = std::string("The resource was not found");
		break;
	case ErrorCodes::NoHost:
		name = std::string("The host could not be found");
		break;
	case ErrorCodes::NotInitialized:
		name = std::string("The algorithm was not initialized");
		break;
	case ErrorCodes::NotSupported:
		name = std::string("The operation is not supported");
		break;
	case ErrorCodes::ReadOnly:
		name = std::string("The stream is read only");
		break;
	case ErrorCodes::RetriesExceeded:
		name = std::string("The number of retries was exceeded");
		break;
	case ErrorCodes::WriteOnly:
		name = std::string("The stream is write only");
		break;
	case ErrorCodes::UnDefined:
		name = std::string("The behavior is undefined");
		break;
	case ErrorCodes::UnKnown:
		name = std::string("An error of unknown origin has occured");
		break;
	default:
		name = std::string("None");
		break;
	}

	return name;
}

NAMESPACE_ENUMERATIONEND