#include "FileEncryption.h"

namespace Example
{
	const std::string FileEncryption::CEFS_ENCRYPT_EXTENSION = ".cenc";
	const std::string FileEncryption::CEFS_ENCRYPT_KEY = ".ckey";

	enum MessageIndex : size_t
	{
		CEFS_ENC_CREATED = 0,
		CEFS_ENC_ABORT = 1,
		CEFS_ENC_SUCCESS = 2,
		CEFS_ENC_FAIL = 3,
		CEFS_KEY_ABORT = 4,
		CEFS_SES_CANCELLED = 5,
		CEFS_KEY_DETECTED = 6,
		CEFS_DEC_PERM = 7,
		CEFS_DEC_SUCCESS = 8,
		CEFS_DEC_FAIL = 9,
		CEFS_DEC_ABORT = 10,
		CEFS_DEC_CANCELLED = 11,
		CEFS_TITLE_LINE1 = 12,
		CEFS_TITLE_LINE2 = 13,
		CEFS_TITLE_LINE3 = 14,
	};
	
	std::vector<std::string> FileEncryption::MessageStrings =
	{
#if defined(CEFS_LANG_ENGLISH)
		std::string("CFES> The key-file has been created at:"),
		std::string("CFES> The encrypted file could not be created, operation aborted."),
		std::string("CFES> The encrypted file has been created at:"),
		std::string("CFES> The file could not be written, check path and directory permissions."),
		std::string("CFES> The key file could not be created, operation aborted."),
		std::string("CFES> Session cancelled, the user aborted the operation."),
		std::string("CFES> The encryption key file was not detected."),
		std::string("CFES> The file could not be written, check path and directory permissions."),
		std::string("CFES> The decrypted file has been created at:"),
		std::string("CFES> The file could not be decrypted, key or file may be damaged."),
		std::string("CFES> The file could not be written, check path and directory permissions."),
		std::string("CFES> Session cancelled, the user aborted the operation."),
		std::string("CFES is a Post Quantum Secure file encryption service."),
		std::string("It uses powerful new symmetric ciphers to encrypt and authenticate a file."),
		std::string("Follow the menus to create a key and encrypt a file, or authenticate and decrypt a file.")
#elif defined(CEFS_LANG_FRENCH)
		std::string("CFES> Le fichier de clés a été créé à:"),
		std::string("CFES> Le fichier chiffré n'a pas pu être créé, opération abandonnée."),
		std::string("CFES> Le fichier crypté a été créé à:"),
		std::string("CFES> Le fichier n'a pas pu être écrit, vérifiez les autorisations de chemin et de répertoire."),
		std::string("CFES> Le fichier de clé n'a pas pu être créé, opération abandonnée."),
		std::string("CFES> Session annulée, l'utilisateur a abandonné l'opération."),
		std::string("CFES> Le fichier de clé de chiffrement n'a pas été détecté."),
		std::string("CFES> Le fichier n'a pas pu être écrit, vérifiez les autorisations de chemin et de répertoire."),
		std::string("CFES> Le fichier déchiffré a été créé à:"),
		std::string("CFES> Le fichier n'a pas pu être déchiffré, la clé ou le fichier peut être endommagé."),
		std::string("CFES> Le fichier n'a pas pu être écrit, vérifiez les autorisations de chemin et de répertoire."),
		std::string("CFES> Session annulée, l'utilisateur a abandonné l'opération."),
		std::string("CFES est un service de chiffrement de fichiers Post Quantum Secure."),
		std::string("Il utilise de nouveaux chiffrements symétriques puissants pour crypter et authentifier un fichier."),
		std::string("Suivez les menus pour créer une clé et crypter un fichier, ou authentifier et décrypter un fichier.")
#elif defined(CEFS_LANG_SPANISH)
		std::string("CFES> El archivo clave se ha creado en:"),
		std::string("CFES> No se pudo crear el archivo encriptado, se canceló la operación."),
		std::string("CFES> El archivo cifrado se ha creado en:"),
		std::string("CFES> El archivo no se pudo escribir, verifique la ruta y los permisos del directorio."),
		std::string("CFES> No se pudo crear el archivo de clave, se canceló la operación."),
		std::string("CFES> Sesión cancelada, el usuario abortó la operación."),
		std::string("CFES> No se detectó el archivo de clave de cifrado."),
		std::string("CFES> El archivo no se pudo escribir, verifique la ruta y los permisos del directorio."),
		std::string("CFES> El archivo descifrado se ha creado en:"),
		std::string("CFES> El archivo no se pudo descifrar, la clave o el archivo pueden estar dañados."),
		std::string("CFES> El archivo no se pudo escribir, verifique la ruta y los permisos del directorio."),
		std::string("CFES> Sesión cancelada, el usuario abortó la operación."),
		std::string("CFES es un servicio de encriptación de archivos Post Quantum Secure."),
		std::string("Utiliza nuevos y potentes cifrados simétricos para cifrar y autenticar un archivo."),
		std::string("Siga los menús para crear una clave y cifrar un archivo, o autenticar y descifrar un archivo.")
#elif defined(CEFS_LANG_GERMAN)
		std::string("CFES> Die Schlüsseldatei wurde erstellt um:"),
		std::string("CFES> Die verschlüsselte Datei konnte nicht erstellt werden, Vorgang abgebrochen."),
		std::string("CFES> Die verschlüsselte Datei wurde erstellt um:"),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen."),
		std::string("CFES> Die Schlüsseldatei konnte nicht erstellt werden, Vorgang abgebrochen."),
		std::string("CFES> Sitzung abgebrochen, der Benutzer hat den Vorgang abgebrochen."),
		std::string("CFES> Die Verschlüsselungsschlüsseldatei wurde nicht erkannt."),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen."),
		std::string("CFES> Die entschlüsselte Datei wurde erstellt um:"),
		std::string("CFES> Die Datei konnte nicht entschlüsselt werden, der Schlüssel oder die Datei sind möglicherweise beschädigt."),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen."),
		std::string("CFES> Sitzung abgebrochen, der Benutzer hat den Vorgang abgebrochen."),
		std::string("CFES ist ein Post Quantum Secure-Dateiverschlüsselungsdienst."),
		std::string("Es verwendet leistungsfähige neue symmetrische Chiffren, um eine Datei zu verschlüsseln und zu authentifizieren."),
		std::string("Befolgen Sie die Menüs, um einen Schlüssel zu erstellen und eine Datei zu verschlüsseln oder eine Datei zu authentifizieren und zu entschlüsseln.")
#elif defined(CEFS_LANG_PORTUGUESE)
		std::string("CFES> O arquivo-chave foi criado em:"),
		std::string("CFES> O arquivo criptografado não pôde ser criado, a operação foi interrompida."),
		std::string("CFES> O arquivo criptografado foi criado em:"),
		std::string("CFES> Não foi possível gravar o arquivo, verifique as permissões de caminho e diretório."),
		std::string("CFES> O arquivo de chave não pôde ser criado, a operação foi interrompida."),
		std::string("CFES> Sessão cancelada, o usuário cancelou a operação."),
		std::string("CFES> O arquivo da chave de criptografia não foi detectado."),
		std::string("CFES> Não foi possível gravar o arquivo, verifique as permissões de caminho e diretório."),
		std::string("CFES> O arquivo descriptografado foi criado em:"),
		std::string("CFES> Não foi possível descriptografar o arquivo, a chave ou o arquivo pode estar danificado."),
		std::string("CFES> Não foi possível gravar o arquivo, verifique as permissões de caminho e diretório."),
		std::string("CFES> Sessão cancelada, o usuário cancelou a operação."),
		std::string("CFES é um serviço de criptografia de arquivos Post Quantum Secure."),
		std::string("Ele usa novas cifras simétricas poderosas para criptografar e autenticar um arquivo."),
		std::string("Siga os menus para criar uma chave e criptografar um arquivo ou autenticar e descriptografar um arquivo.")
#endif
	};

	class FileEncryption::CFESState final
	{
	public:

		SecureVector<byte> key;
		SecureVector<byte> nonce;
		int32_t cmode;
		BlockCiphers bcpr;
		StreamAuthenticators sauth;

		CFESState()
			:
			key(0),
			nonce(0),
			cmode(0),
			bcpr(BlockCiphers::None),
			sauth(StreamAuthenticators::None)
		{};

		~CFESState()
		{
			SecureClear(key);
			SecureClear(nonce);
			cmode = 0;
			bcpr = BlockCiphers::None;
			sauth = StreamAuthenticators::None;
		}
	};

	//~~~Public Functions~~~//

	void FileEncryption::Run()
	{
		int32_t cmode;
		std::string fpath;
		std::string kpath;
		bool encrypt;
		bool res;
		CFESState state;

		fpath = MenuFilePath();
		res = (fpath.size() != 0 && FileTools::Exists(fpath));

		if (res == true)
		{
			encrypt = (ExampleUtils::StringContains(fpath, CEFS_ENCRYPT_EXTENSION) == false);
			kpath = FileTools::Path(fpath) + FileTools::Name(fpath) + CEFS_ENCRYPT_KEY;

			if (encrypt == true)
			{
				cmode = MenuCipherMode();

				if (cmode != 0)
				{
					// initialize the state
					LoadCipherState(state, cmode);


					if (FileTools::Exists(kpath))
					{
						res = MenuDeleteFile(kpath);

						if (res == true)
						{
							res = FileTools::Delete(kpath);
						}
					}

					// create the key file
					res = FileTools::Create(kpath);

					if (res == true)
					{
						// sk = k+n + (ext+cprm+ts)
						std::string ext = FileTools::Extension(fpath);
						const size_t HDRLEN = ext.size() + 2;
						std::string epath;
						SecureVector<byte> tmpr(state.key.size() + state.nonce.size() + HDRLEN);

						// generate the random key and add it to the key array
						SecureGenerate(tmpr, 0, state.key.size() + state.nonce.size());
						MemoryTools::Copy(tmpr, 0, state.key, 0, state.key.size());
						MemoryTools::Copy(tmpr, state.key.size(), state.nonce, 0, state.nonce.size());

						// add the file extension, the cipher code, and the total size to the end of the key-file
						tmpr[tmpr.size() - 1] = HDRLEN;
						tmpr[tmpr.size() - 2] = cmode;
						MemoryTools::Copy(ext, 0, tmpr, state.key.size() + state.nonce.size(), ext.size());

						// create the key file and write the contents
						res = FileTools::Create(kpath);

						if (res == true)
						{
							FileTools::Write(kpath, SecureUnlock(tmpr));
							// notify the user that key has been created
							ExampleUtils::WriteLine(MessageStrings[CEFS_ENC_CREATED]);
							ExampleUtils::WriteLine(kpath);

							// the encrypted file is the file name and path with the .cenc extension
							epath = FileTools::Path(fpath) + FileTools::Name(fpath) + CEFS_ENCRYPT_EXTENSION;
							res = FileTools::Create(epath);

							if (res == true)
							{
								// encrypt the file contents and write to new file
								if (cmode == 1)
								{
									// HBA
									state.bcpr = BlockCiphers::RHXH256;
									res = HBATransform(fpath, epath, state, encrypt);
								}
								else if (cmode == 2)
								{
									state.bcpr = BlockCiphers::RHXH512;
									res = HBATransform(fpath, epath, state, encrypt);
								}
								else
								{
									// RCS
									res = RCSTransform(fpath, epath, state, encrypt);
								}
							}
							else
							{
								ExampleUtils::WriteLine(MessageStrings[CEFS_ENC_ABORT]);
							}
						}

						if (res == true)
						{
							// notify user that file has been written successfully
							ExampleUtils::WriteLine(MessageStrings[CEFS_ENC_SUCCESS]);
							ExampleUtils::WriteLine(epath);
						}
						else
						{
							ExampleUtils::WriteLine(MessageStrings[CEFS_ENC_FAIL]);
						}
					}
					else
					{
						ExampleUtils::WriteLine(MessageStrings[CEFS_KEY_ABORT]);
					}
				}
				else
				{
					ExampleUtils::WriteLine(MessageStrings[CEFS_SES_CANCELLED]);
				}
			}
			else
			{
				// decrypt

				if (FileTools::Exists(kpath) == false)
				{
					ExampleUtils::WriteLine(MessageStrings[CEFS_KEY_DETECTED]);
					kpath = MenuKeyLoad();
				}

				if (kpath.size() != 0 && FileTools::Exists(kpath) == true)
				{
					const size_t FLELEN = FileTools::Size(kpath);
					std::vector<byte> tmpr(FLELEN);
					std::string dpath;
					std::string ext;
					CFESState state;
					int32_t cmode;

					FileTools::Read(kpath, tmpr);

					// parse the footer size, cipher type, and extension
					const size_t HDRLEN = tmpr[tmpr.size() - 1];
					const size_t EXTLEN = HDRLEN - 2;
					cmode = tmpr[tmpr.size() - 2];
					ext.resize(EXTLEN);

					LoadCipherState(state, cmode);
					// copy the key and nonce to state
					MemoryTools::Copy(tmpr, 0, state.key, 0, state.key.size());
					MemoryTools::Copy(tmpr, state.key.size(), state.nonce, 0, state.nonce.size());
					MemoryTools::CopyToObject(tmpr, state.key.size() + state.nonce.size(), (char*)ext.data(), EXTLEN);

					// the decrypted file path and name
					dpath = FileTools::Path(fpath) + FileTools::Name(fpath) + std::string(".") + ext;

					// file exists, delete or abort
					if (FileTools::Exists(dpath) == true)
					{
						res = MenuDeleteFile(dpath);

						if (res == true)
						{
							res = FileTools::Delete(dpath);
						}
					}

					if (res == true)
					{
						// create the decrypted file
						res = FileTools::Create(dpath);

						// decrypt the data to the output file
						if (res == true)
						{
							if (cmode == 1)
							{
								// HBA
								state.bcpr = BlockCiphers::RHXH256;
								res = HBATransform(fpath, dpath, state, encrypt);
							}
							else if (cmode == 2)
							{
								state.bcpr = BlockCiphers::RHXH512;
								res = HBATransform(fpath, dpath, state, encrypt);
							}
							else
							{
								// RCS
								res = RCSTransform(fpath, dpath, state, encrypt);
							}

							if (res == true)
							{
								// notify user that file has been written successfully
								ExampleUtils::WriteLine(MessageStrings[CEFS_DEC_SUCCESS]);
								ExampleUtils::WriteLine(dpath);
							}
							else
							{
								ExampleUtils::WriteLine(MessageStrings[CEFS_DEC_FAIL]);
							}
						}
						else
						{
							ExampleUtils::WriteLine(MessageStrings[CEFS_DEC_PERM]);
						}
					}
					else
					{
						ExampleUtils::WriteLine(MessageStrings[CEFS_DEC_PERM]);
					}
				}
				else
				{
					ExampleUtils::WriteLine(MessageStrings[CEFS_DEC_CANCELLED]);
				}
			}
		}
	}

	void FileEncryption::Help()
	{
		ExampleUtils::WriteLine(MessageStrings[CEFS_TITLE_LINE1]);
		ExampleUtils::WriteLine(MessageStrings[CEFS_TITLE_LINE2]);
		ExampleUtils::WriteLine(MessageStrings[CEFS_TITLE_LINE3]);
		ExampleUtils::WriteLine("");
	}

	void FileEncryption::PrintTitle()
	{
		ExampleUtils::WriteLine("");
		ExampleUtils::WriteLine("CFES - CEX File Encryption Service");
		ExampleUtils::WriteLine("Version 1.0a");
		ExampleUtils::WriteLine("January 12, 2020");
	}

	//~~~Private Functions~~~//

	bool FileEncryption::LoadCipherState(CFESState &State, int32_t CMode)
	{
		bool res;

		switch (CMode)
		{
		case 1:
		{
			State.sauth = StreamAuthenticators::HMACSHA256;
			State.key.resize(32);
			State.nonce.resize(16);
			State.cmode = 1;
			res = true;
			break;
		}
		case 2:
		{
			State.sauth = StreamAuthenticators::HMACSHA512;
			State.key.resize(64);
			State.nonce.resize(16);
			State.cmode = 2;
			res = true;
			break;
		}
		case 3:
		{
			State.sauth = StreamAuthenticators::KMAC256;
			State.key.resize(32);
			State.nonce.resize(32);
			State.cmode = 3;
			res = true;
			break;
		}
		case 4:
		{
			State.sauth = StreamAuthenticators::KMAC512;
			State.key.resize(64);
			State.nonce.resize(32);
			State.cmode = 4;
			res = true;
			break;
		}
		default:
		{
			State.cmode = 0;
			res = false;
		}
		}

		return res;
	}

	bool FileEncryption::HBATransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption)
	{
		// HBA mode
		std::vector<byte> input(0);
		std::vector<byte> output(0);
		const size_t INPLEN = FileTools::Size(InputFile);
		bool res;

		res = false;

		// initialize and key the cipher
		HBA cpr(State.bcpr, State.sauth);
		SymmetricKey kp(State.key, State.nonce);
		cpr.Initialize(Encryption, kp);

		if (Encryption)
		{
			// read from file and size output
			input.resize(INPLEN);
			output.resize(INPLEN + cpr.TagSize());
			FileTools::Read(InputFile, input);

			// encrypt the input plain-text
			cpr.Transform(input, 0, output, 0, input.size());
			FileTools::Write(OutputFile, output);
			res = true;
		}
		else
		{
			input.resize(INPLEN);
			output.resize(INPLEN - cpr.TagSize());
			FileTools::Read(InputFile, input);

			// if authentication fails during transform, and authentication failure exception is thrown,
			// the cipher-text is not decrypted, and this function returns false
			try
			{
				// decrypt the input cipher-text
				cpr.Transform(input, 0, output, 0, output.size());
				FileTools::Write(OutputFile, output);
				res = true;
			}
			catch (CryptoAuthenticationFailure & const)
			{
			}
		}

		return res;
	}

	int32_t FileEncryption::MenuCipherMode()
	{
		std::string rbuf;
		int32_t res;

		while (true)
		{
			ExampleUtils::WriteLine("CFES> Select the cipher and mode of encryption:");
			ExampleUtils::WriteLine("CFES> 0) Cancel the operation");
			ExampleUtils::WriteLine("CFES> 1) HBA-RHX-256 Authenticated mode");
			ExampleUtils::WriteLine("CFES> 2) HBA-RHX-512 Authenticated mode");
			ExampleUtils::WriteLine("CFES> 3) RCS-256 Authenticated stream cipher");
			ExampleUtils::WriteLine("CFES> 4) RCS-512 Authenticated stream cipher");
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("CFES> Make a selection and press enter to proceed");

			rbuf = ExampleUtils::GetResponse();
			ExampleUtils::WriteLine("");

			if (rbuf == "0" || rbuf == "1" || rbuf == "2" || rbuf == "3" || rbuf == "4")
			{
				break;
			}
		};

		res = std::stoi(rbuf);

		return res;
	}

	bool FileEncryption::MenuDeleteFile(std::string &FilePath)
	{
		std::string bres;
		bool ret;

		ret = false;

		while (true)
		{
			ExampleUtils::WriteLine("CFES> The file exists. Press Y and enter to delete existing file, or N and enter to abort.");
			bres = ExampleUtils::GetResponse();

			if (bres == "y" || bres == "Y")
			{
				ret = true;
				break;
			}
			else if (bres == "n" || bres == "N")
			{
				break;
			}
		}

		return ret;
	}

	std::string FileEncryption::MenuFilePath()
	{
		std::string fpath;

		while (true)
		{
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("CFES> Enter the full path to a file, or an empty line to cancel, and press enter");
			fpath = ExampleUtils::GetResponse();

			if (fpath.size() > 8 && FileTools::Exists(fpath) || fpath.size() == 0)
			{
				break;
			}
		}

		return fpath;
	}

	std::string FileEncryption::MenuKeyLoad()
	{
		std::string kpath;

		while (true)
		{
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("CFES> Enter the full path to the key file, or an empty line to cancel, and press enter");
			kpath = ExampleUtils::GetResponse();

			if (kpath.size() > 8 && FileTools::Exists(kpath) || kpath.size() == 0)
			{
				break;
			}
		}

		return kpath;
	}

	int32_t FileEncryption::MenuOperation()
	{
		std::string rbuf;
		int32_t res;

		while (true)
		{
			ExampleUtils::WriteLine("Select from the following menu options:");
			ExampleUtils::WriteLine("0) Cancel the operation");
			ExampleUtils::WriteLine("1) Encrypt a file and output the key");
			ExampleUtils::WriteLine("2) Input a key and Decrypt a file");
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("Make a selection and press enter to proceed");

			rbuf = ExampleUtils::GetResponse();
			ExampleUtils::WriteLine("");

			if (rbuf == "0" || rbuf == "1" || rbuf == "2")
			{
				break;
			}
		};

		res = std::stoi(rbuf);

		return res;
	}

	bool FileEncryption::RCSTransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption)
	{
		// HBA mode
		std::vector<byte> input(0);
		std::vector<byte> output(0);
		const size_t INPLEN = FileTools::Size(InputFile);
		bool res;

		res = false;

		// initialize and key the cipher
		RCS cpr(State.sauth);
		SymmetricKey kp(State.key, State.nonce);
		cpr.Initialize(Encryption, kp);

		if (Encryption)
		{
			// read from file and size output
			input.resize(INPLEN);
			output.resize(INPLEN + cpr.TagSize());
			FileTools::Read(InputFile, input);

			// encrypt the input plain-text
			cpr.Transform(input, 0, output, 0, input.size());
			FileTools::Write(OutputFile, output);
			res = true;
		}
		else
		{
			input.resize(INPLEN);
			output.resize(INPLEN - cpr.TagSize());
			FileTools::Read(InputFile, input);

			// if authentication fails during transform, and authentication failure exception is thrown,
			// the cipher-text is not decrypted, and this function returns false
			try
			{
				// decrypt the input cipher-text
				cpr.Transform(input, 0, output, 0, output.size());
				FileTools::Write(OutputFile, output);
				res = true;
			}
			catch (CryptoAuthenticationFailure & const)
			{
			}
		}

		return res;
	}

	void FileEncryption::SecureGenerate(SecureVector<byte> &Output, size_t Offset, size_t Length)
	{
		ACP gen;

		gen.Generate(Output, Offset, Length);
	}
}