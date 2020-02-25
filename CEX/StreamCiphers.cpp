#include "StreamCiphers.h"

NAMESPACE_ENUMERATION

StreamCiphers StreamCipherConvert::FromName(std::string &Name)
{
	return static_cast<StreamCiphers>(SymmetricCipherConvert::FromName(Name));
}

StreamCiphers StreamCipherConvert::FromDescription(StreamCiphers Enumeral, StreamAuthenticators Authenticator)
{
	StreamCiphers name;

	switch (Enumeral)
	{
		case StreamCiphers::CSX256:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::CSXR20H256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::CSXR20H512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::CSXR20K256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::CSXR20K512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::CSXR20P256;
			}
			else
			{
				name = StreamCiphers::CSX256;
			}
			break;
		}
		case StreamCiphers::CSX512:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::CSXR80H256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::CSXR80H512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::CSXR80K256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::CSXR80K512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::CSXR80P256;
			}
			else
			{
				name = StreamCiphers::CSX512;
			}
			break;
		}
		case StreamCiphers::RCS:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::RCSH256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::RCSH512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::RCSK256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::RCSK512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::RCSP256;
			}
			else
			{
				name = StreamCiphers::RCS;
			}
			break;
		}
		case StreamCiphers::TSX256:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::TSXR72H256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::TSXR72H512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::TSXR72K256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::TSXR72K512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::TSXR72P256;
			}
			else
			{
				name = StreamCiphers::TSX256;
			}
			break;
		}
		case StreamCiphers::TSX512:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::TSXR96H256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::TSXR96H512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::TSXR96K256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::TSXR96K512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::TSXR96P256;
			}
			else
			{
				name = StreamCiphers::TSX512;
			}
			break;
		}
		case StreamCiphers::TSX1024:
		{
			if (Authenticator == StreamAuthenticators::HMACSHA256)
			{
				name = StreamCiphers::TSXR120H256;
			}
			else if (Authenticator == StreamAuthenticators::HMACSHA512)
			{
				name = StreamCiphers::TSXR120H512;
			}
			else if (Authenticator == StreamAuthenticators::KMAC256)
			{
				name = StreamCiphers::TSXR120K256;
			}
			else if (Authenticator == StreamAuthenticators::KMAC512)
			{
				name = StreamCiphers::TSXR120K512;
			}
			else if (Authenticator == StreamAuthenticators::Poly1305)
			{
				name = StreamCiphers::TSXR120P256;
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