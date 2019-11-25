#ifndef CEX_TCPSERVER_H
#define CEX_TCPSERVER_H

#include "CexDomain.h"
#include "MemoryStream.h"
#include "ParallelTools.h"

NAMESPACE_NETWORK

using IO::MemoryStream;

class IAsyncResult
{
public:

	IAsyncResult()
	{
	}

	~IAsyncResult()
	{
	}
};

/// <summary>
/// This class listens for an incoming connection.
/// <para>Start listening for a connection with the Listen method, when a host connects the Connected event is fired.
/// The Connected event contains the connected socket instance in a SocketAsyncEventArgs class.</para>
/// </summary>
class TcpServer
{
public:

	/// <summary>
	/// The Client Connected delegate
	/// </summary>
	/// <param name="owner">The owner object</param>
	/// <param name="args">A <see cref="SocketAsyncEventArgs"/> class</param>
	//void ConnectedDelegate(object owner, SocketAsyncEventArgs args);

	/// <summary>
	/// The Client Connected event; fires each time a connection has been established
	/// </summary>
	//event ConnectedDelegate Connected;

	/// <summary>
	/// The Packet Received delegate
	/// </summary>
	/// <param name="owner">The owner object</param>
	/// <param name="Flag">The socket error flag</param>
	//void DisConnectedDelegate(object owner, SocketError Flag);
	/// <summary>
	/// The Client Connected event; fires each time a connection has been established
	/// </summary>
	//event DisConnectedDelegate DisConnected;

	/// <summary>
	/// The Packet Received delegate
	/// </summary>
	/// <param name="args">A <see cref="DataReceivedEventArgs"/> class</param>
	//void DataReceivedDelegate(DataReceivedEventArgs args);
	/// <summary>
	/// The Data Received event; fires each time data has been received
	/// </summary>
	//event DataReceivedDelegate DataReceived;

	/// <summary>
	/// Start Blocking listen on a port for an incoming connection
	/// </summary>
	/// 
	/// <param name="HostName">The Host Name assigned to this server</param>
	/// <param name="Port">The Port number assigned to this server</param>
	/// <param name="MaxConnections">The maximum number of connections</param>
	/// <param name="Timeout">The wait timeout period</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void Listen(std::string &HostName, int Port, int MaxConnections = 10, int Timeout = 0)
	{
		/*IPHostEntry host;
		IPAddress[] ipList;
		IPAddress ip;

		try
		{
			// address of the host
			host = Dns.GetHostEntry(HostName);
			ipList = host.AddressList;
			ip = ipList[ipList.Length - 1];
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:Listen", "The Tcp listener has failed!", se);
		}
		catch (Exception)
		{
			throw;
		}

		Listen(ip, Port, MaxConnections);*/
	}

	/// <summary>
	/// Start Blocking listen on a port for an incoming connection
	/// </summary>
	/// 
	/// <param name="Address">The IP address assigned to this server</param>
	/// <param name="Port">The Port number assigned to this server</param>
	/// <param name="MaxConnections">The maximum number of connections</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void Listen(std::string &Address, int Port, int MaxConnections = 10)
	{
		/*try
		{
			IPEndPoint ipEP = new IPEndPoint(Address, Port);
			m_lsnSocket = new Socket(ipEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

			if (ipEP.AddressFamily == AddressFamily.InterNetworkV6)
			{
				m_lsnSocket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, false);
				m_lsnSocket.Bind(ipEP);
			}
			else
			{
				// associate the socket with the local endpoint
				m_lsnSocket.Bind(ipEP);
			}

			m_isListening = true;
			// accept the incoming client
			m_lsnSocket.Listen(MaxConnections);
			// assign client and stream
			Socket cltSocket = m_lsnSocket.Accept();

			// get the socket for the accepted client connection and put it into the ReadEventArg object user token
			SocketAsyncEventArgs readEventArgs = new SocketAsyncEventArgs();
			// store the socket
			readEventArgs.UserToken = cltSocket;

			if (Connected != null)
				Connected(this, readEventArgs);

			m_opDone.WaitOne(1);
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:Listen", "The Tcp listener has failed!", se);
		}
		catch (Exception)
		{
			throw;
		}*/
	}

	/// <summary>
	/// Start Non-Blocking listen on a port for an incoming connection
	/// </summary>
	/// 
	/// <param name="HostName">The Host Name assigned to this server</param>
	/// <param name="Port">The Port number assigned to this server</param>
	/// <param name="MaxConnections">The maximum number of connections</param>
	/// <param name="Timeout">The wait timeout period</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void ListenAsync(std::string &HostName, int Port, int MaxConnections = 10, int Timeout = 0)
	{
		/*IPHostEntry host;
		IPAddress[] ipList;
		IPAddress ip;

		try
		{
			host = Dns.GetHostEntry(HostName);
			ipList = host.AddressList;
			ip = ipList[ipList.Length - 1];
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:Listen", "The Tcp listener has failed!", se);
		}
		catch (Exception)
		{
			throw;
		}

		ListenAsync(ip, Port, MaxConnections, Timeout);*/
	}

	/// <summary>
	/// Start Non-Blocking listen on a port for an incoming connection
	/// </summary>
	/// 
	/// <param name="Address">The IP address assigned to this server</param>
	/// <param name="Port">The Port number assigned to this server</param>
	/// <param name="MaxConnections">The maximum number of simultaneous connections allowed (default is 10)</param>
	/// <param name="Timeout">The wait timeout period</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void ListenAsync(std::string &Address, int Port, int MaxConnections = 10, int Timeout = 0)
	{
		/*try
		{
			IPEndPoint ipEP = new IPEndPoint(Address, Port);
			m_lsnSocket = new Socket(ipEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

			if (ipEP.AddressFamily == AddressFamily.InterNetworkV6)
			{
				m_lsnSocket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)27, false);
				m_lsnSocket.Bind(ipEP);
			}
			else
			{
				// associate the socket with the local endpoint
				m_lsnSocket.Bind(ipEP);
			}

			m_isListening = true;
			m_lsnSocket.Listen(MaxConnections);
			// create the state object
			StateToken state = new StateToken(m_lsnSocket);
			// accept the incoming clients
			m_lsnSocket.BeginAccept(new AsyncCallback(ListenCallback), state);
			// blocks the current thread to receive incoming messages
			m_opDone.WaitOne(Timeout);
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:ListenAsync", "The Tcp listener has failed!", se);
		}
		catch (Exception)
		{
			throw;
		}*/
	}

	/// <summary>
	/// The Listen callback
	/// </summary>
	/// 
	/// <param name="Ar">The IAsyncResult</param>
	/// 
	/// <exception cref="CryptoSocketException">Thrown if the Tcp listen operation has failed</exception>
	void ListenCallback(IAsyncResult Ar)
	{
		/*// retrieve the state object and the client socket from the asynchronous state object
		StateToken state = (StateToken)Ar.AsyncState;
		Socket srv = state.Client;

		try
		{
			// get the socket for the accepted client connection and put it into the ReadEventArg object user token
			Socket cltSocket = srv.EndAccept(Ar);

			// store the socket
			SocketAsyncEventArgs readEventArgs = new SocketAsyncEventArgs();
			readEventArgs.UserToken = cltSocket;

			if (Connected != null)
				Connected(this, readEventArgs);

			// create the state object
			state = new StateToken(m_lsnSocket);
			// accept the incoming clients
			m_lsnSocket.BeginAccept(new AsyncCallback(ListenCallback), state);
		}
		catch (ObjectDisposedException)
		{
			// disconnected
			if (DisConnected != null)
				DisConnected(this, SocketError.ConnectionAborted);
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:ListenCallback", "The Tcp listener has failed!", se);
		}
		catch (Exception)
		{
			if (m_isListening)
				throw;
		}*/
	}

	/// <summary>
	/// Stop listening for a connection
	/// </summary>
	void ListenStop()
	{
		/*try
		{
			m_lsnSocket.Close(1);
			m_opDone.WaitOne(10);
			m_isListening = false;
		}
		catch (SocketException se)
		{
			throw new CryptoSocketException("Socket:ListenStop", "The Tcp listen stop had an error!", se);
		}
		catch (Exception)
		{
			throw;
		}*/
	}
};

NAMESPACE_NETWORKEND
#endif
