#include "CFES.h"
#include "ConsoleTools.h"
#include "FileTools.h"
#include "../../CEX/ACP.h"
#include "../../CEX/HBA.h"
#include "../../CEX/RCS.h"

namespace FileEncryptionService
{
	using namespace CEX;
	using Provider::ACP;
	using Enumeration::BlockCiphers;
	using Enumeration::CipherModes;
	using Exception::CryptoAuthenticationFailure;
	using Cipher::Block::Mode::HBA;
	using Cipher::Stream::RCS;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;

	const std::string CFES::CFES_ENCRYPT_EXTENSION = ".cenc";
	const std::string CFES::CFES_KEY_EXTENSION = ".ckey";
	const std::string CEFS_COMMAND_PROMPT = "CFES> ";
	const size_t CEFS_MENU_SIZE = 36;

	std::vector<std::string> CFES::MessageStrings =
	{
		// english
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
		std::string("Follow the menus to create a key and encrypt a file, or authenticate and decrypt a file."),
		std::string("Usage: add the full path to a file when prompted; if the file has a .ckey extension, \ndecryption mode is selected, otherwise the cipher is initialized for encryption."),
		std::string("In encryption mode, a key is generated that uses the file-name and the .ckey extension, \nand an encrypted copy of the file is created with the .cenc extension in the originating directory."),
		std::string("To decrypt a file, put the .ckey and .cenc files in the same directory, \nor specify the full path to the key when prompted."),
		std::string("CFES> The file exists. Press Y and enter to delete existing file, or N and enter to abort."),
		std::string("CFES> Select the cipher and mode of encryption:"),
		std::string("CFES> 0) Cancel the operation"),
		std::string("CFES> 1) HBA-RHX-256 Authenticated mode"),
		std::string("CFES> 2) HBA-RHX-512 Authenticated mode"),
		std::string("CFES> 3) RCS-256 Authenticated stream cipher"),
		std::string("CFES> 4) RCS-512 Authenticated stream cipher"),
		std::string("CFES> Make a selection and press enter to proceed"),
		std::string("CFES> Enter the full path to a file, or an empty line to cancel, and press enter"),
		std::string("CFES> Enter the full path to the key file, or an empty line to cancel, and press enter"),
		std::string("Select from the following menu options:"),
		std::string("0) Cancel the operation"),
		std::string("1) Encrypt a file and output the key"),
		std::string("2) Input a key and Decrypt a file"),
		std::string("Press Y and enter to encrypt another file, any other key to exit."),
		std::string("Delete"),
		std::string("An error has occurred! Press any key to close."),
		std::string("The session was aborted. Press any key to close."),
		// french
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
		std::string("Suivez les menus pour créer une clé et crypter un fichier, ou authentifier et décrypter un fichier."),
		std::string("Utilisation: ajoutez le chemin d'accès complet à un fichier lorsque vous y êtes invité; \nsi le fichier a une extension .ckey, le mode de déchiffrement est sélectionné, sinon le chiffrement est initialisé pour le chiffrement."),
		std::string("En mode de chiffrement, une clé est générée qui utilise le nom de fichier et l'extension .ckey, \net une copie chiffrée du fichier est créée avec l'extension .cenc dans le répertoire d'origine."),
		std::string("Pour décrypter un fichier, placez les fichiers .ckey et .cenc dans le même répertoire ou \nspécifiez le chemin d'accès complet à la clé lorsque vous y êtes invité."),
		std::string("CFES> The file exists. Press Y and enter to delete existing file, or N and enter to abort."),
		std::string("CFES> Sélectionnez le chiffrement et le mode de chiffrement:"),
		std::string("CFES> 0) Annuler l'opération"),
		std::string("CFES> 1) HBA-RHX-256 Mode authentifié"),
		std::string("CFES> 2) HBA-RHX-512 Mode authentifié"),
		std::string("CFES> 3) RCS-256 Chiffrement de flux authentifié"),
		std::string("CFES> 4) RCS-512 Chiffrement de flux authentifié"),
		std::string("CFES> Faites une sélection et appuyez sur Entrée pour continuer"),
		std::string("CFES> Entrez le chemin d'accès complet à un fichier ou une ligne vide pour annuler et appuyez sur Entrée"),
		std::string("CFES> Entrez le chemin d'accès complet au fichier clé ou une ligne vide pour annuler, puis appuyez sur Entrée"),
		std::string("Sélectionnez parmi les options de menu suivantes:"),
		std::string("0) Annuler l'opération"),
		std::string("1) Chiffrer un fichier et sortir la clé"),
		std::string("2) Saisissez une clé et décryptez un fichier"),
		std::string("Appuyez sur Y et entrez pour crypter un autre fichier, n'importe quelle autre clé pour quitter."),
		std::string("Supprimer"),
		std::string("Une erreur est survenue! Appuyez sur n'importe quelle touche pour fermer."),
		std::string("La session a été interrompue. Appuyez sur n'importe quelle touche pour fermer."),
		// spanish
		std::string("CFES> El archivo clave se ha creado en:"),
		std::string("CFES> No se pudo crear el archivo encriptado, se canceló la operación."),
		std::string("CFES> El archivo cifrado se ha creado en:"),
		std::string("CFES> No se pudo escribir el archivo, verifique la ruta y los permisos del directorio."),
		std::string("CFES> No se pudo crear el archivo de clave, se canceló la operación."),
		std::string("CFES> Sesión cancelada, el usuario abortó la operación."),
		std::string("CFES> No se detectó el archivo de clave de cifrado."),
		std::string("CFES> No se pudo escribir el archivo, verifique la ruta y los permisos del directorio."),
		std::string("CFES> El archivo descifrado se ha creado en:"),
		std::string("CFES> No se pudo descifrar el archivo, la clave o el archivo pueden estar dañados."),
		std::string("CFES> No se pudo escribir el archivo, verifique la ruta y los permisos del directorio."),
		std::string("CFES> Sesión cancelada, el usuario abortó la operación."),
		std::string("CFES es un servicio de cifrado de archivos Post Quantum Secure."),
		std::string("Utiliza nuevos y potentes cifrados simétricos para cifrar y autenticar un archivo."),
		std::string("Siga los menús para crear una clave y cifrar un archivo, o autenticar y descifrar un archivo."),
		std::string("Uso: agregue la ruta completa a un archivo cuando se le solicite; si el archivo tiene una extensión .ckey, \nse selecciona el modo de descifrado; de lo contrario, el cifrado se inicializa para el cifrado."),
		std::string("En el modo de cifrado, se genera una clave que utiliza el nombre de archivo y la extensión .ckey, \ny se crea una copia cifrada del archivo con la extensión .cenc en el directorio de origen."),
		std::string("Para descifrar un archivo, coloque los archivos .ckey y .cenc en el mismo directorio, \no especifique la ruta completa a la clave cuando se le solicite."),
		std::string("CFES> El archivo existe. Presione Y e ingrese para eliminar el archivo existente, o N e ingrese para cancelar."),
		std::string("CFES> Seleccione el cifrado y el modo de cifrado:"),
		std::string("CFES> 0) Cancelar la operación"),
		std::string("CFES> 1) Modo autenticado HBA-RHX-256"),
		std::string("CFES> 2) Modo autenticado HBA-RHX-512"),
		std::string("CFES> 3) Cifrado de flujo autenticado RCS-256"),
		std::string("CFES> 4) Cifrado de flujo autenticado RCS-512"),
		std::string("CFES> Seleccione y presione Intro para continuar"),
		std::string("CFES> Ingrese la ruta completa a un archivo, o una línea vacía para cancelar, y presione enter"),
		std::string("CFES> Ingrese la ruta completa al archivo de clave, o una línea vacía para cancelar, y presione enter"),
		std::string("Seleccione entre las siguientes opciones de menú:"),
		std::string("0) Cancelar la operación"),
		std::string("1) Cifre un archivo y envíe la clave"),
		std::string("2) Ingrese una clave y descifre un archivo"),
		std::string("Presione Y e ingrese para cifrar otro archivo, cualquier otra clave para salir."),
		std::string("Eliminar"),
		std::string("¡Se ha producido un error! Presione cualquier tecla para cerrar."),
		std::string("La sesión fue abortada. Presione cualquier tecla para cerrar."),
		// german
		std::string("CFES> Die Schlüsseldatei wurde erstellt unter:"),
		std::string("CFES> Die verschlüsselte Datei konnte nicht erstellt werden, Vorgang abgebrochen."),
		std::string("CFES> Die verschlüsselte Datei wurde erstellt um:"),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen"),
		std::string("CFES> Die Schlüsseldatei konnte nicht erstellt werden, Vorgang abgebrochen."),
		std::string("CFES> Sitzung abgebrochen, der Benutzer hat den Vorgang abgebrochen."),
		std::string("CFES> Die Verschlüsselungsschlüsseldatei wurde nicht erkannt."),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen."),
		std::string("CFES> Die entschlüsselte Datei wurde erstellt um:"),
		std::string("CFES> Die Datei konnte nicht entschlüsselt werden, der Schlüssel oder die Datei sind möglicherweise beschädigt."),
		std::string("CFES> Die Datei konnte nicht geschrieben werden. Überprüfen Sie die Pfad- und Verzeichnisberechtigungen."),
		std::string("CFES> Sitzung abgebrochen, der Benutzer hat den Vorgang abgebrochen."),
		std::string("CFES ist ein Post Quantum Secure-Dateiverschlüsselungsdienst."),
		std::string("Es verwendet leistungsstarke neue symmetrische Chiffren, um eine Datei zu verschlüsseln und zu authentifizieren."),
		std::string("Befolgen Sie die Menüs, um einen Schlüssel zu erstellen und eine Datei zu verschlüsseln oder eine Datei zu authentifizieren und zu entschlüsseln."),
		std::string("Verwendung: Fügen Sie den vollständigen Pfad zu einer Datei hinzu, wenn Sie dazu aufgefordert werden.\n Hat die Datei die Erweiterung .ckey, wird der Entschlüsselungsmodus ausgewählt, andernfalls wird die Verschlüsselung für die Verschlüsselung initialisiert."),
		std::string("Im Verschlüsselungsmodus wird ein Schlüssel generiert, der den Dateinamen und die Erweiterung .ckey verwendet, \nund eine verschlüsselte Kopie der Datei wird mit der Erweiterung .cenc im Ursprungsverzeichnis erstellt."),
		std::string("Um eine Datei zu entschlüsseln, legen Sie die Dateien .ckey und .cenc im selben Verzeichnis ab oder geben \nSie den vollständigen Pfad zum Schlüssel an, wenn Sie dazu aufgefordert werden."),
		std::string("CFES> Die Datei existiert. Drücken Sie J und die Eingabetaste, um eine vorhandene Datei zu löschen, \noder N und die Eingabetaste, um den Vorgang abzubrechen."),
		std::string("CFES> Wählen Sie die Verschlüsselung und den Verschlüsselungsmodus aus:"),
		std::string("CFES> 0) Vorgang abbrechen "),
		std::string("> 1) HBA-RHX-256 Authentifizierter Modus"),
		std::string("CFES> 2) HBA-RHX-512 Authentifizierter Modus"),
		std::string("CFES> 3) RCS-256 Authentifizierte Stream-Verschlüsselung"),
		std::string("CFES> 4) RCS-512 Authentifizierte Stream-Verschlüsselung"),
		std::string("CFES> Treffen Sie eine Auswahl und drücken Sie die Eingabetaste, um fortzufahren"),
		std::string("CFES> Geben Sie den vollständigen Pfad zu einer Datei oder eine leere Zeile zum Abbrechen ein und drücken Sie die Eingabetaste"),
		std::string("CFES> Geben Sie den vollständigen Pfad zur Schlüsseldatei oder eine leere Zeile zum Abbrechen ein und drücken Sie die Eingabetaste"),
		std::string("Wählen Sie aus den folgenden Menüoptionen:"),
		std::string("0) Brechen Sie den Vorgang ab"),
		std::string("1) Verschlüsseln Sie eine Datei und geben Sie den Schlüssel aus"),
		std::string("2) Geben Sie einen Schlüssel ein und entschlüsseln Sie eine Datei"),
		std::string("Drücken Sie Y und geben Sie die Eingabetaste ein, um eine andere Datei zu verschlüsseln."),
		std::string("Löschen"),
		std::string("Ein Fehler ist aufgetreten! Drücken Sie eine beliebige Taste, um zu schließen."),
		std::string("Die Sitzung wurde abgebrochen. Drücken Sie eine beliebige Taste, um zu schließen."),
		// portuguese
		std::string("CFES> O arquivo-chave foi criado em:"),
		std::string("CFES> O arquivo criptografado não pôde ser criado, a operação foi interrompida."),
		std::string("CFES> O arquivo criptografado foi criado em: "),
		std::string("CFES> O arquivo não pôde ser gravado, verifique as permissões de caminho e diretório."),
		std::string("CFES> O arquivo de chave não pôde ser criado, a operação foi interrompida."),
		std::string("CFES> Sessão cancelada, o usuário cancelou a operação."),
		std::string("CFES> O arquivo da chave de criptografia não foi detectado."),
		std::string("CFES> O arquivo não pôde ser gravado, verifique as permissões de caminho e diretório."),
		std::string("CFES> O arquivo descriptografado foi criado em:"),
		std::string("CFES> O arquivo não pôde ser descriptografado, a chave ou o arquivo pode estar danificado."),
		std::string("CFES> O arquivo não pôde ser gravado, verifique as permissões de caminho e diretório."),
		std::string("CFES> Sessão cancelada, o usuário cancelou a operação."),
		std::string("CFES é um serviço de criptografia de arquivos Post Quantum Secure."),
		std::string("Ele usa novas cifras simétricas poderosas para criptografar e autenticar um arquivo."),
		std::string("Siga os menus para criar uma chave e criptografar um arquivo ou autenticar e descriptografar um arquivo."),
		std::string("Uso: adicione o caminho completo a um arquivo quando solicitado; se o arquivo tiver uma extensão .ckey, \no modo de descriptografia será selecionado; caso contrário, a cifra será inicializada para criptografia."),
		std::string("No modo de criptografia, é gerada uma chave que usa o nome do arquivo e a extensão .ckey, \ne uma cópia criptografada do arquivo é criada com a extensão .cenc no diretório de origem."),
		std::string("Para descriptografar um arquivo, coloque os arquivos .ckey e .cenc no mesmo diretório ou especifique o \ncaminho completo para a chave quando solicitado."),
		std::string("CFES> O arquivo existe. Pressione Y e digite para excluir o arquivo existente ou N e digite para abortar."),
		std::string("CFES> Selecione a cifra e o modo de criptografia:"),
		std::string("CFES> 0) Cancelar a operação "),
		std::string("CFES> 1) Modo autenticado HBA-RHX-256"),
		std::string("CFES> 2) Modo autenticado HBA-RHX-512"),
		std::string("CFES> 3) Cifra de fluxo autenticada RCS-256"),
		std::string("CFES> 4) Cifra de fluxo autenticada RCS-512"),
		std::string("CFES> Faça uma seleção e pressione Enter para continuar"),
		std::string("CFES> Digite o caminho completo para um arquivo ou uma linha vazia para cancelar e pressione "),
		std::string("CFES> Digite o caminho completo para o arquivo de chave ou uma linha vazia para cancelar e pressione enter"),
		std::string("Selecione entre as seguintes opções de menu:"),
		std::string("0) Cancele a operação"),
		std::string("1) Criptografar um arquivo e gerar a chave"),
		std::string(") Insira uma chave e descriptografar um arquivo"),
		std::string("Pressione Y e digite para criptografar outro arquivo, qualquer outra tecla para sair."),
		std::string("Excluir"),
		std::string("Ocorreu um erro! Pressione qualquer tecla para fechar."),
		std::string("A sessão foi abortada. Pressione qualquer tecla para fechar."),
		// italian
		std::string("CFES> Il file chiave è stato creato in:"),
		std::string("CFES> Impossibile creare il file crittografato, operazione interrotta."),
		std::string("CFES> Il file crittografato è stato creato in: "),
		std::string("CFES> Impossibile scrivere il file, controllare il percorso e le autorizzazioni della directory."),
		std::string("CFES> Impossibile creare il file chiave, operazione interrotta."),
		std::string("CFES> Sessione annullata, l'utente ha interrotto l'operazione."),
		std::string("CFES> Il file della chiave di crittografia non è stato rilevato."),
		std::string("CFES> Impossibile scrivere il file, controllare il percorso e le autorizzazioni della directory."),
		std::string("CFES> Il file decrittografato è stato creato in: "),
		std::string("CFES> Impossibile decrittografare il file, la chiave o il file potrebbero essere danneggiati."),
		std::string("CFES> Impossibile scrivere il file, controllare il percorso e le autorizzazioni della directory."),
		std::string("CFES> Sessione annullata, l'utente ha interrotto l'operazione."),
		std::string("CFES è un servizio di crittografia di file Post Quantum Secure."),
		std::string("Utilizza potenti nuove cifre simmetriche per crittografare e autenticare un file."),
		std::string("Seguire i menu per creare una chiave e crittografare un file oppure autenticare e decrittografare un file."),
		std::string("Utilizzo: aggiungi il percorso completo a un file quando richiesto; se il file ha un'estensione .ckey, \n viene selezionata la modalità di crittografia \n, altrimenti il ​​codice viene inizializzato per la crittografia."),
		std::string("In modalità crittografia, viene generata una chiave che utilizza il nome file e l'estensione .ckey, \n ne viene creata una copia crittografata del file con l'estensione .cenc nella directory di origine."),
		std::string("Per decrittografare un file, inserire i file .ckey e .cenc nella stessa directory, \n né specificare il percorso completo della chiave quando richiesto."),
		std::string("CFES> Il file esiste. Premi Y e invio per eliminare il file esistente, oppure N e invio per interrompere."),
		std::string("CFES> Seleziona la cifra e la modalità di crittografia:"),
		std::string("CFES> 0) Annullare l'operazione"),
		std::string("CFES> 1) HBA-RHX-256 Modalità autenticata"),
		std::string("CFES> 2) HBA-RHX-512 Modalità autenticata"),
		std::string("CFES> 3) RCS-256 Crittografia di flusso autenticata"),
		std::string("CFES> 4) RCS-512 Crittografia di flusso autenticata"),
		std::string("CFES> Effettua una selezione e premi Invio per procedere"),
		std::string("CFES> Immettere il percorso completo di un file o una riga vuota per annullare, quindi premere Invio"),
		std::string("CFES> Immettere il percorso completo per il file chiave o una riga vuota per annullare, quindi premere Invio"),
		std::string("Selezionare dalle seguenti opzioni di menu:"),
		std::string("0) Annulla l'operazione"),
		std::string("1) Crittografa un file e genera la chiave"),
		std::string("2) Immettere una chiave e decrittografare un file"),
		std::string("Premi Y e invio per crittografare un altro file, qualsiasi altro tasto per uscire."),
		std::string("Elimina"),
		std::string("C'è stato un errore! Premere un tasto qualsiasi per chiudere."),
		std::string("La sessione è stata interrotta. Premere un tasto qualsiasi per chiudere.")
		/*// future - add a new language index
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string(""),
		std::string("")*/
	};

	class CFES::CFESState
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

	void CFES::Run()
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
			encrypt = (ConsoleTools::StringContains(fpath, CFES_ENCRYPT_EXTENSION) == false);
			kpath = FileTools::Path(fpath) + FileTools::Name(fpath) + CFES_KEY_EXTENSION;

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

					if (res == true)
					{
						// create the key file
						res = FileTools::Create(kpath);

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
						tmpr[tmpr.size() - 1] = static_cast<byte>(HDRLEN);
						tmpr[tmpr.size() - 2] = static_cast<byte>(cmode);
						MemoryTools::Copy(ext, 0, tmpr, state.key.size() + state.nonce.size(), ext.size());

						// create the key file and write the contents
						res = FileTools::Create(kpath);

						if (res == true)
						{
							FileTools::Write(kpath, SecureUnlock(tmpr));
							// notify the user that key has been created
							PrintMessage(MessageIndex::CEFS_ENC_CREATED);
							ConsoleTools::WriteLine(kpath);

							// the encrypted file is the file name and path with the .cenc extension
							epath = FileTools::Path(fpath) + FileTools::Name(fpath) + CFES_ENCRYPT_EXTENSION;

							if (FileTools::Exists(epath))
							{
								res = MenuDeleteFile(epath);

								if (res == true)
								{
									res = FileTools::Delete(epath);
								}
							}

							if (res == true)
							{
								res = FileTools::Create(epath);

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
								PrintMessage(MessageIndex::CEFS_ENC_ABORT);
							}
						}

						if (res == true)
						{
							// notify user that file has been written successfully
							PrintMessage(MessageIndex::CEFS_ENC_SUCCESS);
							ConsoleTools::WriteLine(epath);
						}
						else
						{
							PrintMessage(MessageIndex::CEFS_ENC_FAIL);
						}
					}
					else
					{
						PrintMessage(MessageIndex::CEFS_KEY_ABORT);
					}
				}
				else
				{
					PrintMessage(MessageIndex::CEFS_SES_CANCELLED);
				}
			}
			else
			{
				// decrypt

				if (FileTools::Exists(kpath) == false)
				{
					PrintMessage(MessageIndex::CEFS_KEY_DETECTED);
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
								PrintMessage(MessageIndex::CEFS_DEC_SUCCESS);
								ConsoleTools::WriteLine(dpath);
							}
							else
							{
								PrintMessage(MessageIndex::CEFS_DEC_FAIL);
							}
						}
						else
						{
							PrintMessage(MessageIndex::CEFS_DEC_PERM);
						}
					}
					else
					{
						PrintMessage(MessageIndex::CEFS_DEC_PERM);
					}
				}
				else
				{
					PrintMessage(MessageIndex::CEFS_DEC_CANCELLED);
				}
			}
		}
	}

	void CFES::Help()
	{
		PrintMessage(MessageIndex::CEFS_TITLE_LINE1);
		PrintMessage(MessageIndex::CEFS_TITLE_LINE2);
		PrintMessage(MessageIndex::CEFS_TITLE_LINE3);
		PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
		PrintMessage(MessageIndex::CEFS_HELP_LINE1);
		PrintMessage(MessageIndex::CEFS_HELP_LINE2);
		PrintMessage(MessageIndex::CEFS_HELP_LINE3);
	}

	void CFES::PrintTitle()
	{
		ConsoleTools::WriteLine("CFES - CEX File Encryption Service");
		ConsoleTools::WriteLine("Version 1.0a");
		ConsoleTools::WriteLine("January 12, 2020");
		ConsoleTools::WriteLine("CEX++ -Digital Freedom Defence-");
		PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
	}

	void CFES::PrintMessage(MessageIndex Index)
	{
		size_t idx;

		idx = static_cast<size_t>(LanguageIndex()) + static_cast<size_t>(Index);

		if (Index == MessageIndex::CEFS_EMPTY_LINE)
		{
			ConsoleTools::WriteLine("");
		}
		else
		{
			ConsoleTools::WriteLine(MessageStrings[idx]);
		}
	}

	//~~~Private Functions~~~//

	bool CFES::LoadCipherState(CFESState &State, int32_t CMode)
	{
		bool res;

		switch (CMode)
		{
		case 1:
		{
			State.sauth = StreamAuthenticators::HMACSHA2256;
			State.key.resize(32);
			State.nonce.resize(16);
			State.cmode = 1;
			res = true;
			break;
		}
		case 2:
		{
			State.sauth = StreamAuthenticators::HMACSHA2512;
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

	bool CFES::HBATransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption)
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
			catch (const CryptoAuthenticationFailure &)
			{
			}
		}

		return res;
	}

	size_t CFES::LanguageIndex()
	{
		std::string lng;
		size_t idx;

		lng = ConsoleTools::GetLanguage();

		// e=0,f=1,s=2,g=3,p=4 * CEFS_MENU_SIZE
		if (lng.empty() || lng.find("EN") != std::string::npos)
		{
			idx = 0;
		}
		else if (lng.find("FR") != std::string::npos)
		{
			idx = CEFS_MENU_SIZE;
		}
		else if (lng.find("ES") != std::string::npos)
		{
			idx = CEFS_MENU_SIZE * 2;
		}
		else if (lng.find("DE") != std::string::npos)
		{
			idx = CEFS_MENU_SIZE * 3;
		}
		else if (lng.find("PT") != std::string::npos)
		{
			idx = CEFS_MENU_SIZE * 4;
		}
		else if (lng.find("IT") != std::string::npos)
		{
			idx = CEFS_MENU_SIZE * 5;
		}
		else
		{
			idx = 0;
		}

		return idx;
	}

	int32_t CFES::MenuCipherMode()
	{
		std::string rbuf;
		int32_t res;

		while (true)
		{
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE2);
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE3);
			PrintMessage(MessageIndex::CEFS_MENU_LINE4);
			PrintMessage(MessageIndex::CEFS_MENU_LINE5);
			PrintMessage(MessageIndex::CEFS_MENU_LINE6);
			PrintMessage(MessageIndex::CEFS_MENU_LINE7);
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE8);

			rbuf = ConsoleTools::GetResponse();
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);

			if (rbuf == "0" || rbuf == "1" || rbuf == "2" || rbuf == "3" || rbuf == "4")
			{
				break;
			}
		};

		res = std::stoi(rbuf);

		return res;
	}

	bool CFES::MenuDeleteFile(std::string &FilePath)
	{
		std::string bres;
		bool ret;

		ret = false;

		while (true)
		{
			PrintMessage(MessageIndex::CEFS_MENU_LINE1);
			ConsoleTools::WriteLine(MessageStrings[static_cast<size_t>(MessageIndex::CEFS_MENU_LINE16)] + std::string(" ") + FilePath + std::string("?"));
			bres = ConsoleTools::GetResponse();

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

	std::string CFES::MenuFilePath()
	{
		std::string fpath;

		while (true)
		{
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE9);
			fpath = ConsoleTools::GetResponse();

			if (fpath.size() > 8 && FileTools::Exists(fpath) || fpath.size() == 0)
			{
				break;
			}
		}

		return fpath;
	}

	std::string CFES::MenuKeyLoad()
	{
		std::string kpath;

		while (true)
		{
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE10);
			kpath = ConsoleTools::GetResponse();

			if (kpath.size() > 8 && FileTools::Exists(kpath) || kpath.size() == 0)
			{
				break;
			}
		}

		return kpath;
	}

	int32_t CFES::MenuOperation()
	{
		std::string rbuf;
		int32_t res;

		while (true)
		{
			PrintMessage(MessageIndex::CEFS_MENU_LINE11);
			PrintMessage(MessageIndex::CEFS_MENU_LINE12);
			PrintMessage(MessageIndex::CEFS_MENU_LINE13);
			PrintMessage(MessageIndex::CEFS_MENU_LINE14);
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);
			PrintMessage(MessageIndex::CEFS_MENU_LINE8);

			rbuf = ConsoleTools::GetResponse();
			PrintMessage(MessageIndex::CEFS_EMPTY_LINE);

			if (rbuf == "0" || rbuf == "1" || rbuf == "2")
			{
				break;
			}
		};

		res = std::stoi(rbuf);

		return res;
	}

	bool CFES::RCSTransform(const std::string &InputFile, const std::string &OutputFile, CFESState &State, bool Encryption)
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
			catch (const CryptoAuthenticationFailure &)
			{
			}
		}

		return res;
	}

	void CFES::SecureGenerate(SecureVector<byte> &Output, size_t Offset, size_t Length)
	{
		ACP gen;

		gen.Generate(Output, Offset, Length);
	}
}