#include "SocketSender.h"
#include "IntegerTools.h"

NAMESPACE_NETWORK

using Utility::IntegerTools;

#if defined(CEX_WINDOWS_SOCKETS)

SocketSender::SocketSender(socket_t &Source)
	:
	m_sourceSocket(Source),
	m_resultPending(false),
	m_lastResult(0)
{
	m_event.AttachHandle(CreateEvent(NULL, true, false, NULL), true);

	if (!m_event.HandleValid())
	{
		throw CryptoSocketException(std::string("SocketBase"), std::string("Ctor"), std::string("The socket is invalid!"), ErrorCodes::SocketFailure);
	}

	memset(&m_overlapped, 0, sizeof(m_overlapped));
	m_overlapped.hEvent = m_event;
}

SocketSender::~SocketSender()
{
#if defined(CEX_WINDOWS_SOCKETS)
	CancelIo((HANDLE)m_sourceSocket);
#endif
}

void SocketSender::Send(const byte* buf, size_t bufLen)
{
	CEXASSERT(!m_resultPending, "the socket is waiting for data.");

	DWORD written;

	written = 0;

	WSABUF wsabuf =
	{
		IntegerTools::Min((size_t)128 * 1024, bufLen),
		(char*)buf
	};

	if (WSASend(m_sourceSocket, &wsabuf, 1, &written, 0, &m_overlapped, NULL) == 0)
	{
		m_resultPending = false;
		m_lastResult = written;
	}
	else
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			throw CryptoSocketException(std::string("SocketSender"), std::string("Send"), std::string("The socket encountered an error!"), ErrorCodes::SocketFailure);
		}

		m_resultPending = true;
	}
}

void SocketSender::SendEof()
{
	CEXASSERT(!m_resultPending, "the socket is waiting for data.");
	int res;

	res = shutdown(m_sourceSocket, static_cast<int>(SocketShutdownFlags::Send));

	if (res == SOCKET_ERROR)
	{
		throw CryptoSocketException(std::string("SocketSender"), std::string("ShutDown"), std::string("The socket shutdown function has errored!"), ErrorCodes::SocketFailure);
	}

	closesocket(m_sourceSocket);
	ResetEvent(m_event);
	WSAEventSelect(m_sourceSocket, m_event, FD_CLOSE);
	m_resultPending = true;
}

bool SocketSender::EofSent()
{
	if (m_resultPending)
	{
		WSANETWORKEVENTS events;
		WSAEnumNetworkEvents(m_sourceSocket, m_event, &events);

		if ((events.lNetworkEvents & FD_CLOSE) != FD_CLOSE)
		{
			throw CryptoSocketException(std::string("SocketSender"), std::string("EofSent"), std::string("The socket encountered an error!"), ErrorCodes::SocketFailure);
		}

		if (events.iErrorCode[FD_CLOSE_BIT] != 0)
		{
			throw CryptoSocketException(std::string("SocketSender"), std::string("EofSent"), std::string("The socket encountered an error!"), ErrorCodes::SocketFailure);
		}

		m_resultPending = false;
	}
	return m_lastResult != 0;
}

uint SocketSender::GetSendResult()
{
	DWORD flags;
	BOOL result;

	if (m_resultPending)
	{
		flags = 0;
		result = WSAGetOverlappedResult(m_sourceSocket, &m_overlapped, &m_lastResult, false, &flags);
		m_resultPending = false;
	}

	return m_lastResult;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &Container, const CallStack &Stack)
{
	if (m_resultPending)
	{
		Container.AddHandle(m_event, CallStack("SocketSender::GetWaitObjects() - result pending", &Stack));
	}
	else
	{
		Container.SetNoWait(CallStack("SocketSender::GetWaitObjects() - result ready", &Stack));
	}
}

#elif defined(CEX_BERKELEY_SOCKETS)


SocketSender::SocketSender(socket_t &Source)
	: 
	m_sourceSocket(Source),
	m_lastResult(0)
{
}

void SocketSender::Send(const byte* Buffer, size_t BufLen)
{
	m_lastResult = SocketBase::Send(m_sourceSocket, Buffer, BufLen);
}

void SocketSender::SendEof()
{
	SocketBase::ShutDown(m_sourceSocket, SD_SEND);
}

unsigned int SocketSender::GetSendResult()
{
	return m_lastResult;
}

void SocketSender::GetWaitObjects(WaitObjectContainer &Container, const CallStack &Stack)
{
	Container.AddWriteFd(m_sourceSocket, CallStack("SocketSender::GetWaitObjects()", &Stack));
}

#endif
NAMESPACE_NETWORKEND