#include "StreamCiphers.h"

NAMESPACE_ENUMERATION

StreamCiphers StreamCipherConvert::FromName(std::string &Name)
{
	return static_cast<StreamCiphers>(SymmetricCipherConvert::FromName(Name));
}

StreamCiphers StreamCipherConvert::FromDescription(StreamCiphers Enumeral, StreamAuthenticators Authenticator)
{
	StreamCiphers name;

	name = StreamCiphers::None;

	switch (Enumeral)
	{
		case StreamCiphers::CSX256:
		{
			if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::CSXR20K256;
			}
			else
			{
				name = StreamCiphers::CSX256;
			}
			break;
		}
		case StreamCiphers::CSX512:
		{
			if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::CSXR80K512;
			}
			else
			{
				name = StreamCiphers::CSX512;
			}
			break;
		}
		case StreamCiphers::RCS:
		{
			if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::RCSK256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::RCSK512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC1024)
			{
				name = StreamCiphers::RCSK1024;
			}
			else
			{
				name = StreamCiphers::RCS;
			}
			break;
		}
		case StreamCiphers::RWS:
		{
			if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::RWSK256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::RWSK512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC1024)
			{
				name = StreamCiphers::RWSK1024;
			}
			else
			{
				name = StreamCiphers::RWS;
			}
			break;
		}
		case StreamCiphers::TSX256:
		{
			if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::TSXR72K256;
			}
			else
			{
				name = StreamCiphers::TSX256;
			}
			break;
		}
		case StreamCiphers::TSX512:
		{
			if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::TSXR96K512;
			}
			else
			{
				name = StreamCiphers::TSX512;
			}
			break;
		}
		case StreamCiphers::TSX1024:
		{
			if (Authenticator == StreamAuthenticators::KMAC1024)
			{
				name = StreamCiphers::TSXR120K1024;
			}
			else
			{
				name = StreamCiphers::TSX1024;
			}
			break;
		}
	}

	return name;
}

std::string StreamCipherConvert::ToName(StreamCiphers Enumeral)
{
	return SymmetricCipherConvert::ToName(static_cast<SymmetricCiphers>(Enumeral));
}

NAMESPACE_ENUMERATIONEND