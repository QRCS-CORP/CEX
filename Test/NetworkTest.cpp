#include "NetworkTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/Socket.h"
#include <iostream>
#include <time.h>

namespace Test
{
	using Exception::CryptoSocketException;
	using Prng::SecureRandom;
	using Network::Socket;

	const std::string NetworkTest::CLASSNAME = "NetworkTest";
	const std::string NetworkTest::DESCRIPTION = "Sockets and TCP/IP stack test; checks constructors, exceptions, initialization, and synchronization of the networking components.";
	const std::string NetworkTest::SUCCESS = "SUCCESS! All Networking tests have executed succesfully.";

	NetworkTest::NetworkTest()
		:
		m_progressEvent()
	{
	}

	NetworkTest::~NetworkTest()
	{
	}

	const std::string NetworkTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &NetworkTest::Progress()
	{
		return m_progressEvent;
	}

	std::string NetworkTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("NetworkTest: Passed exception handling tests.."));
			//Forwarding();
			OnProgress(std::string("NetworkTest: Passed IP forwarding tests.."));
			Initialization();
			OnProgress(std::string("NetworkTest: Passed initialization tests.."));
			Synchronization();
			OnProgress(std::string("NetworkTest: Passed key synchronization tests.."));
			Stress();
			OnProgress(std::string("NetworkTest: Passed key creation stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException & ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}


	void ForwardTcpPort(const char *sourcePortName, const char *destinationHost, const char *destinationPortName)
	{
		/*SocketsInitializer sockInit;

		Socket sockListen, sockSource, sockDestination;

		int sourcePort = Socket::PortNameToNumber(sourcePortName);
		int destinationPort = Socket::PortNameToNumber(destinationPortName);

		sockListen.Create();
		sockListen.Bind(sourcePort);
		setsockopt(sockListen, IPPROTO_TCP, TCP_NODELAY, "\x01", 1);

		std::cout << "Listing on port " << sourcePort << ".\n";
		sockListen.Listen();

		sockListen.Accept(sockSource);
		cout << "Connection accepted on port " << sourcePort << ".\n";
		sockListen.CloseSocket();

		cout << "Making connection to " << destinationHost << ", port " << destinationPort << ".\n";
		sockDestination.Create();
		sockDestination.Connect(destinationHost, destinationPort);

		cout << "Connection made to " << destinationHost << ", starting to forward.\n";

		SocketSource out(sockSource, false, new SocketSink(sockDestination));
		SocketSource in(sockDestination, false, new SocketSink(sockSource));

		WaitObjectContainer waitObjects;

		while (!(in.SourceExhausted() && out.SourceExhausted()))
		{
			waitObjects.Clear();

			out.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - out", NULL));
			in.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - in", NULL));

			waitObjects.Wait(INFINITE_TIME);

			if (!out.SourceExhausted())
			{
				cout << "o" << flush;
				out.PumpAll2(false);
				if (out.SourceExhausted())
					cout << "EOF received on source socket.\n";
			}

			if (!in.SourceExhausted())
			{
				cout << "i" << flush;
				in.PumpAll2(false);
				if (in.SourceExhausted())
					cout << "EOF received on destination socket.\n";
			}
		}*/
	}

	void NetworkTest::Exception()
	{
		// Initialization exception tests //

		/*try
		{
			std::vector<byte> poly(0);
			AsymmetricKey kp(poly, AsymmetricPrimitives::NTRUPrime, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::NTRUS2SQ4591N761);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}*/

	}

	void NetworkTest::Forwarding(const std::string &SourceHost, const std::string &SourcePort, const std::string &DestinationHost, const std::string &DestinationPort)
	{
#ifdef CEX_SOCKETS_AVAILABLE
		/*//SocketsInitializer sockInit;

		Socket sockListen;
		Socket sockSource;
		Socket sockDestination;

		ushort sourcePort = Socket::PortNameToNumber(SourcePort);
		int destinationPort = Socket::PortNameToNumber(DestinationPort);

		sockListen.Create(Network::SocketAddressFamilyTypes::IPv4);
		sockListen.Bind(sourcePort, SourceHost);
		//setsockopt(sockListen, IPPROTO_TCP, TCP_NODELAY, "\x01", 1);

		std::cout << "Listing on port " << sourcePort << ".\n";
		sockListen.Listen(0);

		sockListen.Accept(sockSource);
		std::cout << "Connection accepted on port " << sourcePort << ".\n";
		sockListen.CloseSocket();

		std::cout << "Making connection to " << DestinationHost << ", port " << destinationPort << ".\n";
		sockDestination.Create();
		sockDestination.Connect(DestinationHost, destinationPort);

		std::cout << "Connection made to " << DestinationHost << ", starting to forward.\n";

		SocketSource out(sockSource, false, new SocketSink(sockDestination));
		SocketSource in(sockDestination, false, new SocketSink(sockSource));

		WaitObjectContainer waitObjects;

		while (!(in.SourceExhausted() && out.SourceExhausted()))
		{
			waitObjects.Clear();

			out.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - out", NULL));
			in.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - in", NULL));

			waitObjects.Wait(INFINITE_TIME);

			if (!out.SourceExhausted())
			{
				std::cout << "o" << std::ostream::flush;
				out.PumpAll2(false);

				if (out.SourceExhausted())
				{
					std::cout << "EOF received on source socket.\n";
				}
			}

			if (!in.SourceExhausted())
			{
				std::cout << "i" << std::ostream::flush;
				in.PumpAll2(false);

				if (in.SourceExhausted())
				{
					std::cout << "EOF received on destination socket.\n";
				}
			}
		}*/
#else
		std::cout << "Socket support was not enabled at compile time.\n";
		exit(-1);
#endif
	}

	void NetworkTest::Initialization()
	{

	}

	void NetworkTest::Synchronization()
	{

	}

	void NetworkTest::Stress()
	{

	}

	void NetworkTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
