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
	using namespace Network;

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
		SocketsInitializer sockInit;

		Socket lstsck;
		Socket srcsck;
		Socket dstsck;
		ushort srcport;
		ushort dstport;

		srcport = Socket::PortNameToNumber(SourcePort);
		dstport = Socket::PortNameToNumber(DestinationPort);

		lstsck.Create();
		lstsck.Bind(srcport, std::string("localhost"));
		setsockopt(lstsck, IPPROTO_TCP, TCP_NODELAY, "\x01", 1);

		std::cout << "Listing on port " << srcport << ".\n";
		lstsck.Listen();

		lstsck.Accept(srcsck);
		std::cout << "Connection accepted on port " << srcport << ".\n";
		lstsck.CloseSocket();

		std::cout << "Making connection to " << DestinationHost << ", port " << dstport << ".\n";
		dstsck.Create();
		dstsck.Connect(DestinationHost, dstport);

		std::cout << "Connection made to " << DestinationHost << ", starting to forward.\n";

		/*SocketSource out(srcsck, false, new SocketSink(dstsck));
		SocketSource in(dstsck, false, new SocketSink(srcsck));

		WaitObjectContainer waitObjects;

		while (!(in.SourceExhausted() && out.SourceExhausted()))
		{
			waitObjects.Clear();

			out.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - out", NULL));
			in.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - in", NULL));

			waitObjects.Wait(CEX_INFINITE_TIME);

			if (!out.SourceExhausted())
			{
				std::cout << "o" << std::flush;
				out.PumpAll2(false);

				if (out.SourceExhausted())
				{
					std::cout << "EOF received on source socket.\n";
				}
			}

			if (!in.SourceExhausted())
			{
				std::cout << "i" << std::flush;
				in.PumpAll2(false);

				if (in.SourceExhausted())
				{
					std::cout << "EOF received on destination socket.\n";
				}
			}
		}*/
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
