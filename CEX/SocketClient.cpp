#include "SocketClient.h"
#include "NetworkTools.h"

NAMESPACE_NETWORK

using Tools::NetworkTools;

//~~~Constructors~~~//

SocketClient::SocketClient(SocketAddressFamilies AddressFamily, SocketProtocols SocketProtocol, SocketTransports SocketTransport)
	:
	m_baseSocket(AddressFamily != SocketAddressFamilies::None ?
		AddressFamily :
		throw CryptoSocketException(std::string("SocketClient"), std::string("Ctor"), std::string("The address family can not be none!"), ErrorCodes::InvalidParam), 
	SocketProtocol != SocketProtocols::None ?
		SocketProtocol :
		throw CryptoSocketException(std::string("SocketClient"), std::string("Ctor"), std::string("The protocol can not be none!"), ErrorCodes::InvalidParam),
	SocketTransport != SocketTransports::None ?
		SocketTransport :
		throw CryptoSocketException(std::string("SocketClient"), std::string("Ctor"), std::string("The transport can not be none!"), ErrorCodes::InvalidParam))
{
#if defined(CEX_OS_WINDOWS)
	SocketBase::StartSockets();
#endif
}

SocketClient::SocketClient(Socket &Source)
	:
	m_baseSocket(Source)
{
#if defined(CEX_OS_WINDOWS)
	SocketBase::StartSockets();
#endif
}

SocketClient::~SocketClient()
{
	m_baseSocket.Clear();

#if defined(CEX_OS_WINDOWS)
	SocketBase::ShutDownSockets();
#endif
}

//~~~Accessors~~~//

SocketAddressFamilies SocketClient::AddressFamily()
{
	return m_baseSocket.AddressFamily;
}

Socket &SocketClient::BaseSocket()
{
	return m_baseSocket;
}

SocketProtocols SocketClient::SocketProtocol()
{
	return m_baseSocket.SocketProtocol;
}

SocketTransports SocketClient::SocketTransport()
{
	return m_baseSocket.SocketTransport;
}

//~~~Public Functions~~~//

bool SocketClient::Connect(const std::string &Host, std::string &Service)
{
	bool ret;

	ret = false;

	if (m_baseSocket.AddressFamily == SocketAddressFamilies::IPv4)
	{
		ipv4_info info = NetworkTools::GetIPv4Info(Host, Service);
		ret = Connect(info.address, info.port);

		if (ret == true)
		{
			OnSocketConnected(1, ipv4_address::ToString(info.address));
		}
	}
	else
	{
		ipv6_info info = NetworkTools::GetIPv6Info(Host, Service);
		ret = Connect(info.address, info.port);

		if (ret == true)
		{
			OnSocketConnected(1, ipv6_address::ToString(info.address));
		}
	}

	return ret;
}

bool SocketClient::Connect(const ipv4_address &Address, uint16_t Port)
{
	bool ret;

	// create the socket
	if (SocketBase::Create(m_baseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketClient"), std::string("Connect"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// connect
	ret = SocketBase::Connect(m_baseSocket, Address, Port);

	if (ret == true)
	{
		OnSocketConnected(1, ipv4_address::ToString(Address));
	}
	else
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The connection was refused"));
	}

	return ret;
}

bool SocketClient::Connect(const ipv6_address &Address, uint16_t Port)
{
	bool ret;

	// create the socket
	if (SocketBase::Create(m_baseSocket) == false)
	{
		throw CryptoSocketException(std::string("SocketClient"), std::string("Connect"), std::string("The socket could not be created!"), ErrorCodes::SocketInvalid);
	}

	// connect
	ret = SocketBase::Connect(m_baseSocket, Address, Port);

	if (ret == true)
	{
		OnSocketConnected(1, ipv6_address::ToString(Address));
	}
	else
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The connection was refused"));
	}

	return ret;
}

void SocketClient::ConnectAsync(const std::string &Address, uint16_t Port)
{
	IAsyncResult* ar = new IAsyncResult(m_baseSocket, Address, static_cast<uint32_t>(Port));
	std::function<void(IAsyncResult*)> f = [this](IAsyncResult* x) { ConnectCallback(x); };
	std::packaged_task<void(IAsyncResult*)> task(f);
	std::future<void> result = task.get_future();
	std::thread thd = std::thread(std::move(task), ar);
	thd.detach();
}

void SocketClient::ConnectCallback(IAsyncResult* Result)
{
	std::mutex m;
	std::unique_lock<std::mutex> lock(m);
	bool ret;

	if (Result != nullptr)
	{
		ret = Connect(Result->Address, static_cast<uint16_t>(Result->Option));


		if (ret == true)
		{
			OnSocketConnected(0, Result->Address);
		}
		else
		{
			OnSocketError(SocketBase::GetLastError(), std::string("The host is unreachable"));
		}

		delete Result;
	}
}

uint32_t SocketClient::Receive(std::vector<uint8_t> &Output, SocketReceiveFlags Flags)
{
	uint32_t ret;

	ret = 0;

	try
	{
		ret = SocketBase::Receive(m_baseSocket, Output, Flags);
	}
	catch (CryptoSocketException&)
	{
		throw;
	}

	if (ret == 0)
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The data receive function received no data"));
	}

	return ret;
}

uint32_t SocketClient::Receive(size_t BufferLength, SocketReceiveFlags Flags)
{
	uint32_t ret;
	std::vector<uint8_t> otp(BufferLength);
	ret = 0;

	try
	{
		ret = SocketBase::Receive(m_baseSocket, otp, Flags);
	}
	catch(CryptoSocketException&)
	{
		throw;
	}

	if (ret != 0)
	{
		otp.resize(ret);
		OnSocketReceived(1, otp);
	}
	else
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The data receive function received no data"));
	}

	return ret;
}

void SocketClient::ReceiveAsync(size_t BufferLength, SocketReceiveFlags Flags)
{
	IAsyncResult* ar = new IAsyncResult(m_baseSocket, static_cast<uint32_t>(BufferLength), static_cast<uint32_t>(Flags));
	std::function<void(IAsyncResult*)> f = [this](IAsyncResult* x) { ReceiveCallback(x); };
	std::packaged_task<void(IAsyncResult*)> task(f);
	std::future<void> result = task.get_future();
	std::thread thd = std::thread(std::move(task), ar);
	thd.detach();
}

void SocketClient::ReceiveCallback(IAsyncResult* Result)
{
	std::mutex m;
	std::unique_lock<std::mutex> lock(m);
	uint32_t ret(0);

	if (Result != nullptr)
	{
		std::vector<uint8_t> otp(Result->Option);

		try
		{
			while (true)
			{
				ret = SocketBase::Receive(Result->Parent, otp, static_cast<SocketReceiveFlags>(Result->Flag));

				if (ret == 0)
				{
					break;
				}

				OnSocketReceived(ret, otp);
			}
		}
		catch (CryptoSocketException &ex)
		{
			OnSocketError(SocketBase::GetLastError(), ex.Message());
		}

		SocketBase::CloseSocket(Result->Parent);
		OnSocketDisconnected(0, "The socket was closed normally");

		delete Result;
	}
}

uint32_t SocketClient::Send(const std::vector<uint8_t> &Input, size_t Length, SocketSendFlags Flags)
{
	uint32_t ret;

	ret = 0;

	try
	{
		ret = SocketBase::Send(m_baseSocket, Input, Length, Flags);
	}
	catch (CryptoSocketException&)
	{
		throw;
	}

	if (ret != 0)
	{
		OnSocketSent(ret);
	}
	else
	{
		OnSocketError(SocketBase::GetLastError(), std::string("The data send function sent no data"));
	}

	return ret;
}

void SocketClient::SendAsync(const std::vector<uint8_t> &Input, size_t Length, SocketSendFlags Flags)
{
	IAsyncResult* ar = new IAsyncResult(m_baseSocket, Input, static_cast<uint32_t>(Length), static_cast<uint32_t>(Flags));
	std::function<void(IAsyncResult*)> f = [this](IAsyncResult* x) { SendCallback(x); };
	std::packaged_task<void(IAsyncResult*)> task(f);
	std::future<void> result = task.get_future();
	std::thread thd = std::thread(std::move(task), ar);
	thd.detach();
}

void SocketClient::SendCallback(IAsyncResult* Result)
{
	std::mutex m;
	std::unique_lock<std::mutex> lock(m);
	uint32_t ret;

	if (Result != nullptr)
	{
		ret = 0;

		try
		{
			ret = SocketBase::Send(Result->Parent, Result->Data, Result->Option, static_cast<SocketSendFlags>(Result->Flag));
		}
		catch (CryptoSocketException &ex)
		{
			OnSocketError(SocketBase::GetLastError(), ex.Message());
		}

		if (ret != 0)
		{
			OnSocketSent(ret);
		}
		else
		{
			OnSocketError(SocketBase::GetLastError(), std::string("The data send function sent no data"));
		}

		delete Result;
	}
}

void SocketClient::ShutDown()
{
	try
	{
		SocketBase::ShutDown(m_baseSocket, SocketShutdownFlags::Receive);
	}
	catch (CryptoSocketException&)
	{
		throw;
	}

	OnSocketDisconnected(m_baseSocket.InstanceCount, "The socket at address: " + m_baseSocket.Address + " was disconnected");

	m_baseSocket.Clear();
}

NAMESPACE_NETWORKEND