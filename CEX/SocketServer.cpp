#include "SocketServer.h"

NAMESPACE_NETWORK

//~~~State~~~//
class SocketServer::SocketServerState
{
public:

	Socket BaseSocket;
	std::vector<Socket*> SocketPool;
	uint32_t BackLog;
	uint32_t MaxConnections;
	std::atomic_uint InstanceCounter;
	std::atomic_bool IsClosed;
	std::atomic_bool IsListening;

	SocketServerState(SocketAddressFamilies AddressFamily, SocketProtocols SocketProtocol, SocketTransports SocketTransport)
		:
		BaseSocket(AddressFamily != SocketAddressFamilies::None ?
			AddressFamily :
			throw CryptoSocketException(std::string("SocketServer"), std::string("Ctor"), std::string("The address family can not be none!"), ErrorCodes::InvalidParam),
			SocketProtocol != SocketProtocols::None ?
			SocketProtocol :
			throw CryptoSocketException(std::string("SocketServer"), std::string("Ctor"), std::string("The protocol can not be none!"), ErrorCodes::InvalidParam),
			SocketTransport != SocketTransports::None ?
			SocketTransport :
			throw CryptoSocketException(std::string("SocketServer"), std::string("Ctor"), std::string("The transport can not be none!"), ErrorCodes::InvalidParam)),
		SocketPool(0),
		BackLog(DEF_BACKLOG),
		MaxConnections(MAX_SOCKETS),
		InstanceCounter(0),
		IsClosed(false),
		IsListening(false)
	{
	}

	~SocketServerState()
	{
		Reset();
	}

	void Reset()
	{
		size_t i;

		BaseSocket.Clear();

		if (SocketPool.size() != 0)
		{
			for (i = 0; i < SocketPool.size(); ++i)
			{
				if (SocketPool[i] != nullptr)
				{
					Socket* s = SocketPool[i];
					SocketBase::CloseSocket(*s);
					delete s;
					SocketPool.erase(SocketPool.begin() + i);
				}
			}

			SocketPool.clear();
		}

		BackLog = 0;
		MaxConnections = 0;
		InstanceCounter = 0;
		IsClosed = false;
		IsListening = false;
	}
};

//~~~Constructors~~~//

SocketServer::SocketServer(SocketAddressFamilies AddressFamily, SocketProtocols SocketProtocol, SocketTransports SocketTransport)
	:
	m_socketServerState(new SocketServerState(AddressFamily, SocketProtocol, SocketTransport)),
	m_ayncListener(nullptr)
{
#if defined(CEX_OS_WINDOWS)
	SocketBase::StartSockets();
#endif
}

SocketServer::~SocketServer()
{
	ListenStop();

#if defined(CEX_OS_WINDOWS)
	SocketBase::ShutDownSockets();
#endif
}

//~~~Accessors~~~//

SocketAddressFamilies SocketServer::AddressFamily()
{
	return m_socketServerState->BaseSocket.AddressFamily;
}

uint32_t &SocketServer::Backlog()
{
	return m_socketServerState->BackLog;
}

bool SocketServer::IsClosed()
{
	return m_socketServerState->IsClosed;
}

bool SocketServer::IsListening()
{
	return m_socketServerState->IsListening;
}

uint32_t &SocketServer::MaxConnections()
{
	return m_socketServerState->MaxConnections;
}

SocketProtocols SocketServer::SocketProtocol()
{
	return m_socketServerState->BaseSocket.SocketProtocol;
}

SocketTransports SocketServer::SocketTransport()
{
	return m_socketServerState->BaseSocket.SocketTransport;
}

//~~~Public Functions~~~//

Socket SocketServer::Listen(const ipv4_address &Address, uint16_t Port)
{
	Socket target;

	// create the socket
	if (SocketBase::Create(m_socketServerState->BaseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// bind the socket
	if (SocketBase::Bind(m_socketServerState->BaseSocket, Address, Port) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket could not be bound!"), ErrorCodes::SocketRefused);
	}

	// listen for incoming connections
	if (SocketBase::Listen(m_socketServerState->BaseSocket, Backlog()) == true)
	{
		m_socketServerState->IsListening = true;
	}
	else
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket failed to enter the listening state!"), ErrorCodes::SocketFailure);
	}

	// blocking wait for a connection
	if (SocketBase::Accept(m_socketServerState->BaseSocket, target) == false)
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The connection was refused"));
	}
	else
	{
		OnSocketAccepted(1, target);
	}

	// shutdown the listening socket
	ShutDown();

	return target;
}

Socket SocketServer::Listen(const ipv6_address &Address, uint16_t Port)
{
	Socket target;

	// create the socket
	if (SocketBase::Create(m_socketServerState->BaseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// bind the socket
	if (SocketBase::Bind(m_socketServerState->BaseSocket, Address, Port) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket could not be bound!"), ErrorCodes::SocketRefused);
	}

	// listen for incoming connections
	if (SocketBase::Listen(m_socketServerState->BaseSocket, Backlog()) == true)
	{
		m_socketServerState->IsListening = true;
	}
	else
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("Listen"), std::string("The socket failed to enter the listening state!"), ErrorCodes::SocketFailure);
	}

	// blocking wait for a connection
	if (SocketBase::Accept(m_socketServerState->BaseSocket, target) == false)
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The connection was refused"));
	}
	else
	{
		OnSocketAccepted(1, target);
	}

	// shutdown the listening socket
	ShutDown();

	return target;
}

void SocketServer::ListenAsync(const ipv4_address &Address, uint16_t Port)
{
	// create the socket
	if (SocketBase::Create(m_socketServerState->BaseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("ListenAsync"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// set the socket options
	SetOptions();

	// bind the socket
	if (SocketBase::Bind(m_socketServerState->BaseSocket, Address, Port) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("ListenAsync"), std::string("The socket could not be bound!"), ErrorCodes::SocketRefused);
	}

	// listen for incoming connections
	if (SocketBase::Listen(m_socketServerState->BaseSocket, Backlog()) == true)
	{
		std::function<void()> f = [this]() { AcceptBegin(); };
		std::packaged_task<void()> task(f);
		std::future<void> result = task.get_future();
		m_ayncListener = new std::thread(std::move(task));

		m_socketServerState->IsListening = true;
		m_ayncListener->detach();
		//thd->join(); // Note: for testing, remove!
	}
	else
	{
		SocketBase::CloseSocket(m_socketServerState->BaseSocket);
		OnSocketError(SocketBase::GetLastError(), std::string("The socket could not enter the listening state"));
	}
}

void SocketServer::ListenAsync(const ipv6_address &Address, uint16_t Port)
{
	// create the socket
	if (SocketBase::Create(m_socketServerState->BaseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("ListenAsync"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// set the socket options
	SetOptions();

	// bind the socket
	if (SocketBase::Bind(m_socketServerState->BaseSocket, Address, Port) == false)
	{
		throw CryptoSocketException(std::string("SocketServer"), std::string("ListenAsync"), std::string("The socket could not be bound!"), ErrorCodes::SocketRefused);
	}

	// listen for incoming connections
	if (SocketBase::Listen(m_socketServerState->BaseSocket, Backlog()) == true)
	{
		std::function<void()> f = [this]() { AcceptBegin(); };
		std::packaged_task<void()> task(f);
		std::future<void> result = task.get_future();
		m_ayncListener = new std::thread(std::move(task));

		m_socketServerState->IsListening = true;
		m_ayncListener->detach();
	}
	else
	{
		SocketBase::CloseSocket(m_socketServerState->BaseSocket);
		OnSocketError(SocketBase::GetLastError(), std::string("The socket could not enter the listening state"));
	}
}

void SocketServer::ListenStop()
{
	size_t i;

	for (i = 0; i < m_socketServerState->SocketPool.size(); ++i)
	{
		Socket* sk = m_socketServerState->SocketPool[i];

		if (sk != nullptr)
		{
			if (SocketBase::IsConnected(*sk) == true)
			{
				SocketBase::ShutDown(*sk, SocketShutdownFlags::Both);
			}

			m_socketServerState->SocketPool.erase(m_socketServerState->SocketPool.begin() + i);

			delete sk;
		}
	}

	if (m_ayncListener != nullptr)
	{
		delete m_ayncListener;
	}
}

void SocketServer::ShutDown()
{
	std::mutex m;
	std::unique_lock<std::mutex> lock(m);
	size_t i;

	ListenStop();

	for (i = 0; i < m_socketServerState->SocketPool.size(); ++i)
	{
		Socket* s = m_socketServerState->SocketPool[i];

		if (s != nullptr)
		{
			try
			{
				SocketBase::ShutDown(*s, SocketShutdownFlags::Both);
			}
			catch (CryptoSocketException&)
			{
				OnSocketError(SocketExceptions::SocketShutDown, std::string("The child socket did not shutdown gracefully"));
			}

			delete s;
		}
	}

	m_socketServerState->SocketPool.clear();

	try
	{
		SocketBase::ShutDown(m_socketServerState->BaseSocket, SocketShutdownFlags::Both);
	}
	catch(CryptoSocketException&)
	{
		throw;
	}

	m_socketServerState->BaseSocket.Clear();
}

//~~~Private Functions~~~//

void SocketServer::AcceptBegin()
{
	std::mutex m;
	std::unique_lock<std::mutex> lock(m);

	// accept connection requests while open
	while (!IsClosed())
	{
		m_socketServerState->InstanceCounter -= PollSockets();

		if (m_socketServerState->SocketPool.size() < MaxConnections())
		{
			// engage the accept callback
			++m_socketServerState->InstanceCounter;
			IAsyncResult* ar = new IAsyncResult(m_socketServerState->BaseSocket, m_socketServerState->InstanceCounter);
			AcceptCallback(ar);
		}
	}

	// join threads and delete all sockets
	AcceptEnd();
}

void SocketServer::AcceptCallback(IAsyncResult* Result)
{

	if (Result != nullptr)
	{
		Socket* target = new Socket(Result->Parent.AddressFamily, Result->Parent.SocketProtocol, Result->Parent.SocketTransport);
		target->InstanceCount = Result->Option;

		if (SocketBase::Accept(Result->Parent, *target) == false)
		{
			// delete the socket
			delete target;
			// signal the error
			OnSocketError(SocketBase::GetLastError(), std::string("The connection was refused or timed out"));
		}
		else
		{
			// send the socket to the main thread
			OnAsyncSocketAccepted(target->InstanceCount, *target);
			// add the socket to the pool
			m_socketServerState->SocketPool.push_back(target);
		}

		delete Result;
	}
}

void SocketServer::AcceptEnd()
{
	ListenStop();
}

uint32_t SocketServer::PollSockets()
{
	size_t i;
	uint32_t ret;

	ret = 0;

	for (i = 0; i < m_socketServerState->SocketPool.size(); ++i)
	{
		Socket* sk = m_socketServerState->SocketPool[i];

		if (sk != nullptr && SocketBase::IsConnected(*sk) == false)
		{
			m_socketServerState->SocketPool.erase(m_socketServerState->SocketPool.begin() + i);
			delete sk;
			++ret;
		}
	}

	return ret;
}

void SocketServer::SetOptions()
{
#if defined(CEX_OS_WINDOWS)
	char code;
#else
	int32_t code;
#endif

	code = 1;
	setsockopt(m_socketServerState->BaseSocket.Connection, SOL_SOCKET, SO_REUSEADDR, &code, sizeof(code));

#if defined(CEX_OS_POSIX)
	setsockopt(m_socketServerState->BaseSocket.Connection, SOL_SOCKET, SO_REUSEPORT, &code, sizeof(code));
#endif
}

NAMESPACE_NETWORKEND
