#include "SocketReceiver.h"
#include "IntegerTools.h"

NAMESPACE_NETWORK

using Utility::IntegerTools;

#if defined(CEX_WINDOWS_SOCKETS)

SocketReceiver::SocketReceiver(socket_t &Source)
	:
	m_sourceSocket(Source),
	m_resultPending(false),
	m_eofReceived(false)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);

	if (!m_event.HandleValid())
	{
		throw CryptoSocketException(std::string("SocketBase"), std::string("Ctor"), std::string("The socket is invalid!"), ErrorCodes::SocketFailure);
	}

	std::memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

SocketReceiver::~SocketReceiver()
{
	CancelIo((HANDLE)m_sourceSocket);
}

bool SocketReceiver::Receive(byte* Buffer, size_t BufLen)
{
	CEXASSERT(!m_resultPending && !m_eofReceived, "the socket has not been initialized.");

	DWORD flags;
	// don't queue too much at once, or we might use up non-paged memory
	WSABUF wsabuf =
	{
		IntegerTools::Min((size_t)128 * 1024, BufLen), (char*)Buffer
	};

	flags = 0;

	if (WSARecv(m_sourceSocket, &wsabuf, 1, &m_lastResult, &flags, &m_overlapped, NULL) == 0)
	{
		if (m_lastResult == 0)
		{
			m_eofReceived = true;
		}
	}
	else
	{
		switch (WSAGetLastError())
		{
			case WSAEDISCON:
			{
				m_lastResult = 0;
				m_eofReceived = true;
				break;
			}
			case WSA_IO_PENDING:
			{
				m_resultPending = true;
				break;
			}
			default:
			{
				throw CryptoSocketException(std::string("SocketReceiver"), std::string("Receive"), std::string("The socket has encountered an error!"), ErrorCodes::SocketFailure);
			}
		}
	}

	return !m_resultPending;
}

void SocketReceiver::GetWaitObjects(WaitObjectContainer &Container, const CallStack &Stack)
{
	if (m_resultPending)
	{
		Container.AddHandle(m_event, CallStack("SocketReceiver::GetWaitObjects() - result pending", &Stack));
	}
	else if (!m_eofReceived)
	{
		Container.SetNoWait(CallStack("SocketReceiver::GetWaitObjects() - result ready", &Stack));
	}
}

uint SocketReceiver::GetReceiveResult()
{
	DWORD flags;

	if (m_resultPending)
	{
		flags = 0;

		if (WSAGetOverlappedResult(m_sourceSocket, &m_overlapped, &m_lastResult, false, &flags))
		{
			if (m_lastResult == 0)
			{
				m_eofReceived = true;
			}
		}
		else
		{
			switch (WSAGetLastError())
			{
				case WSAEDISCON:
				{
					m_lastResult = 0;
					m_eofReceived = true;
					break;
				}
				default:
				{
					throw CryptoSocketException(std::string("SocketReceiver"), std::string("GetReceiveResult"), std::string("The socket encountered an error!"), ErrorCodes::SocketFailure);
				}
			}
		}

		m_resultPending = false;
	}

	return m_lastResult;
}

#elif defined(CEX_BERKELEY_SOCKETS)

SocketReceiver::SocketReceiver(socket_t &Source)
	:
	m_sourceSocket(Source),
	m_lastResult(0),
	m_eofReceived(false)
{
}

void SocketReceiver::GetWaitObjects(WaitObjectContainer &container, const CallStack &Stack)
{
	if (!m_eofReceived)
	{
		container.AddReadFd(m_sourceSocket, CallStack("SocketReceiver::GetWaitObjects()", &Stack));
	}
}

bool SocketReceiver::Receive(byte* Buffer, size_t BufLen)
{
	m_lastResult = SocketBase::Receive(m_sourceSocket, Buffer, BufLen);

	if (BufLen > 0 && m_lastResult == 0)
	{
		m_eofReceived = true;
	}

	return true;
}

uint SocketReceiver::GetReceiveResult()
{
	return m_lastResult;
}
#endif

NAMESPACE_NETWORKEND