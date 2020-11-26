#ifndef QSHEILD_QSS_H
#define QSHEILD_QSS_H

#include "Common.h"
#include "ConsoleTools.h"
#include "MessageIndex.h"
#include "../../CEX/InternetAddress.h"
#include "../../CEX/SecureVector.h"
#include "../../CEX/Socket.h"
#include "../../CEX/SocketClient.h"
#include "../../CEX/SocketExceptions.h"
#include "../../CEX/SocketServer.h"
#include <mutex>

namespace QuantumShield
{
	using CEX::ipv4_address;
	using CEX::ipv6_address;
	using CEX::SecureVector;
	using CEX::Network::Socket;
	using CEX::Network::SocketClient;
	using CEX::Enumeration::SocketExceptions;
	using CEX::Network::SocketServer;

	/// <summary>
	/// QSS state options
	/// </summary>
	class QSSState final
	{
	public:

		bool IPv6Enabled;
		bool MultiThreaded;

		QSSState()
			:
			IPv6Enabled(false),
			MultiThreaded(false)
		{
		}

		~QSSState()
		{
			IPv6Enabled = false;
			MultiThreaded = false;
		}
	};

	class QSS final
	{
	private:

		static const size_t QSS_MENU_SIZE = 36;
		static const ushort QSS_DEF_PORT = 1776;
		static const std::string QSS_KEY_EXTENSION;
		static const std::string QSS_COMMAND_PROMPT;
		static std::vector<std::string> MessageStrings;

		QSSState m_serverState;
		SocketServer m_serverSocket;
		std::vector<SocketClient> m_socketPool;
		bool m_isRunning;
		bool m_isConnected;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// The constructor
		/// </summary>
		///
		/// <param name="State">The server state</param>
		QSS(QSSState &State);

		/// <summary>
		/// The destructor
		/// </summary>
		~QSS();

		bool IsConnected()
		{
			return m_isConnected;
		}

		//~~~Public Functions~~~//

		/// <summary>
		/// Start and instance of the server listener
		/// </summary>
		///
		/// <param name="Address">The IPv4 address structure</param>
		/// <param name="Port">The listening port number</param>
		void Run(const ipv4_address &Address, ushort Port = QSS_DEF_PORT)
		{
			std::function<void(int, const std::string&)> socketclosedhandler = [this](int x, const std::string &y) { SocketClosed(x, y); };
			m_serverSocket.OnSocketClosed += socketclosedhandler;

			std::function<void(SocketExceptions, const std::string&)> socketerrorhandler = [this](SocketExceptions x, const std::string &y) { SocketError(x, y); };
			m_serverSocket.OnSocketError += socketerrorhandler;

			if (m_serverState.MultiThreaded)
			{
				std::function<void(int, Socket&)> socketasyncaccepthandler = [this](int x, Socket &y) { SocketAsyncAccepted(x, y); };
				m_serverSocket.OnAsyncSocketAccepted += socketasyncaccepthandler;

				m_serverSocket.ListenAsync(Address, Port);
			}
			else
			{
				Socket s = m_serverSocket.Listen(Address, Port);
				SocketClient clt(s);

				std::function<void(int)> socketsendhandler = [this](int x) { SocketSend(x); };
				clt.OnSocketSent += socketsendhandler;

				std::function<void(int, const std::vector<byte>&)> socketreceivedhandler = [this](int x, const std::vector<byte> &y) { SocketReceived(x, y); };
				clt.OnSocketReceived += socketreceivedhandler;

				m_socketPool.push_back(clt);
			}
		}

		std::vector<SocketClient> &SocketPool()
		{
			return m_socketPool;
		}

		/// <summary>
		/// Start and instance of the server listener
		/// </summary>
		///
		/// <param name="Address">The IPv6 address structure</param>
		/// <param name="Port">The listening port number</param>
		void Run(const ipv6_address &Address, ushort Port = QSS_DEF_PORT);

		/// <summary>
		/// Shutdown the server
		/// </summary>
		void Quit()
		{
			m_serverSocket.ShutDown();
		}

		//~~~Callbacks~~~//

		/// <summary>
		/// A synchronous socket has been connected
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		void SocketAsyncAccepted(int Identity, Socket &Connection)
		{
			std::mutex mm;
			std::unique_lock<std::mutex>();

			ConsoleTools::Print("Server connected to: " + Connection.Address);
			Socket s = Connection;
			SocketClient clt(s);

			std::function<void(int)> socketsendhandler = [this](int x) { SocketSend(x); };
			clt.OnSocketSent += socketsendhandler;

			std::function<void(int, const std::vector<byte>&)> socketreceivedhandler = [this](int x, const std::vector<byte> &y) { SocketReceived(x, y); };
			clt.OnSocketReceived += socketreceivedhandler;

			m_socketPool.push_back(clt);
			m_isConnected = true;
		}

		/// <summary>
		/// A socket has been closed
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		/// <param name="Message">The servers shutdown message</param>
		void SocketClosed(int Identity, const std::string &Message)
		{
			ConsoleTools::Print("Server socket closed: " + Message);
		}

		/// <summary>
		/// An error has occured
		/// </summary>
		///
		/// <param name="Error">The socket exception code</param>
		/// <param name="Message">The error message</param>
		void SocketError(SocketExceptions Error, const std::string &Message)
		{
			ConsoleTools::Print("Server error: " + Message);
		}

		/// <summary>
		/// A socket has received data from the remote host
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		/// <param name="Output">Data received from the remote host</param>
		void SocketReceived(int Identity, const std::vector<byte> &Output)
		{
			std::string msg((char*)Output.data());

			ConsoleTools::Print("Client> " + msg);
		}

		/// <summary>
		/// The socket has sent data to the remote host
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		void SocketSend(int Identity)
		{
			ConsoleTools::Print("Data has been transmitted");
		}

		//~~~Static Functions~~~//

		/// <summary>
		/// Display the help menu
		/// </summary>
		static void Help();

		/// <summary>
		/// Print the application title
		/// </summary>
		static void PrintTitle();

		/// <summary>
		/// Print a message to the console
		/// </summary>
		///
		/// <param name="Index">The message index</param>
		static void PrintMessage(MessageIndex Index);

		/// <summary>
		/// Ask the user a question posed Y or N
		/// </summary>
		///
		/// <param name="Index">The message index</param>
		static bool UserQuery(MessageIndex Index);

	private:

		static size_t LanguageIndex();
	};
}

#endif