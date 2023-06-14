import requests
from hexdump import hexdump
from collections.abc import Iterable
import json
import logging
import tempfile


from .nexauth import NexAuth


logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')


# PLC in encrypted mode uses HTTPS with self signed certificate
# requests issue a warning that certification verification is recommended
# we don't have any way to validate certificate, so we suppress the warning
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

class NexError(Exception): pass

class Http:
    def __init__(self, url, encrypted, auth, certfile):
        self.url = ('https' if encrypted else 'http') + '://' + url
        self.auth = requests.auth.HTTPDigestAuth(*auth)
        self.session = requests.Session()
        self.cert = certfile

    def get(self, url):
        print(f'http get: {url}')
        try: res = self.session.get(url=self.url + url,auth=self.auth, timeout=3, verify=False, cert=self.cert)
        except Exception as e:
            raise NexError('HTTP POST error') from e
        return res

    def post(self, data):
        logging.info(f'HTTP POST {self.url}: {data}')
        try: res = self.session.post(url=self.url, data=data, auth=self.auth, timeout=3, verify=False, cert=self.cert)
        except Exception as e:
            raise NexError('HTTP POST error') from e

        if res.status_code != 200 or 'Error' in res.headers:
            if 'Error' in res.headers:
                raise NexError(res.headers['Error'])
            else:
                raise NexError(f'expected HTTP POST result code 200 (HTTP OK), got {res.status_code} instead')
            
        return res

    def xpost(self, path, data, req_headers={}):
        u = self.url + path
        res = self.session.post(url=u, data=data, auth=self.auth, timeout=3, verify=False, cert=self.cert, headers=req_headers)
        return res
    

class NexPLC:
    description_files = [
        'CPUDescription.xml',
        'Systems.xml',
        'Version.xml',
        'utif/BuiltInIO.xml',
        'utif/CpuUnit.xml',
        'utif/ECAT.xml',
        'utif/EIP.xml',
        'utif/FINS.xml',
        'utif/MCE.xml',
        'utif/NXBUS.xml',
        'utif/Networks.xml',
        'utif/PLC.xml',
        'utif/Subsystems.xml',
        'utif/UserInfo.xml',
        'utif/Version.xml',
        'utif/network_ECAT.xml',
        'utif/network_EIP.xml',
        'utif/Peripherals.xml',
        'utif/PowerSupply.xml',
        'utif/ControllerOperationTime.xml',
        'utif/PLCInternalLog.xml',

    ]

    def __init__(self, host, encrypted=False, credentials=None):
        self.host = host

        if credentials is None:
            nexAuth = NexAuth()
            username, password = nexAuth.getLogin(encrypted)
            certfile = nexAuth.getCertificateFilename() if encrypted else None
        else:
            if encrypted:
                username = credentials.data['encrypted_login']
                password = credentials.data['encrypted_password']
                cert_data = credentials.data['encrypted_certificate']
                f = tempfile.NamedTemporaryFile(delete=False)
                f.write(cert_data.encode())
                f.flush()
                f.close()
                certfile = f.name

            else:
                username = credentials.data['login']
                password = credentials.data['password']
                certfile = None

        auth = (username, password) 
        
        self.cpu_fcgi = Http(f'{self.host}/cgi-bin/cpu.fcgi', encrypted, auth, certfile)
        self.ecat_fcgi = Http(f'{self.host}/cgi-bin/ecat.fcgi', encrypted, auth, certfile)
        self.nxbus_fcgi = Http(f'{self.host}/cgi-bin/nxbus.fcgi', encrypted, auth, certfile)
        self.webapi_fcgi = Http(f'{self.host}/cgi-bin/WebAPI.fcgi', encrypted, auth, certfile)
        self.http = Http(f'{self.host}', encrypted, auth, certfile)


    ## -------------------------------------------------------------------------
    ## Basic CPU functions
    ## -------------------------------------------------------------------------        

    def CPU_getModel(self):
        r = self.cpu_fcgi.post('CPU_getModel')
        return r.text.strip()

    def CPU_getPLCName(self):
        r = self.cpu_fcgi.post('CPU_getPLCName')
        return r.text

    def CPU_setPLCName(self, newname):
        self.cpu_fcgi.post(f'CPU_setPLCName {newname}')

    def CPU_getUnitVersion(self):
        r = self.cpu_fcgi.post('CPU_getUnitVersion')
        return r.text

    def CPU_getStatus(self):
        ''' Returns: ['RUN', 'NoError']
        '''
        r = self.cpu_fcgi.post('CPU_getStatus')
        return r.text.split(',')

    def CPU_getStatusExtended(self):
        ''' Returns: 1 user=1970-01-01:03:28:01,vendor= ECAT=0,BuiltInIO=0,NXBus=0 0000
        '''
        r = self.cpu_fcgi.post('CPU_getStatusExtend')
        return r.text

    def CPU_getTaskList(self):
        ''' Returns: 1 PrimaryTask,Base,4000000
        '''
        r = self.cpu_fcgi.post('CPU_getTaskList')
        return r.text

    def CPU_getTaskInfo(self, task='PrimaryTask'):
        ''' Returns: 0,191471,234900,105400,198595,196465,119685,128925,127410,132225,128550,122225
        '''
        r = self.cpu_fcgi.post(f'CPU_getTaskInfo {task}')
        return r.text

    def CPU_getMode(self):
        r = self.cpu_fcgi.post('CPU_getMode')
        return r.text

    def CPU_setMode(self, mode):
        if mode == 0: mode = 'program'
        if mode == 4: mode = 'run'
        r = self.cpu_fcgi.post(f'CPU_setMode mode={mode}')

    def CPU_getLibraryVersion(self):
        # FIXME: NexError: CPU 0101 Command format error.
        r = self.cpu_fcgi.post('CPU_getLibraryVersion')
        return r.text

    def CPU_getTotalPowerOnTime(self):
        r = self.cpu_fcgi.post('CPU_getTotalPowerOnTime')
        return r.text.strip()
        # returns: 'CPU 63123' ... what is meaning?

    def CPU_startBlinkLED(self):
        #!! self.cpu_fcgi.post(f'CPU_startBlinkLED') causes system to crash (power cycle required)
        pass
    
    def CPU_stopBlinkLED(self):
        # self.cpu_fcgi.post(f'CPU_stopBlinkLED')
        pass

    ##CPU_setCPUID
    ##CPU_acquireAccessRight
    ##CPU_releaseAccessRight
    ##CPU_forceReleaseAccessRight
    ##CPU_setWriteProtect
    ##CPU_getWriteProtectStatus
    ##CPU_clearAllMemory
    ##CPU_clearAllMemoryEx
    ##CPU_reset
    ##CPU_resetEx
    ##CPU_resetTaskExecTime
    ##CPU_getProgramList
    ##CPU_getConditionFlags
    ##CPU_notifyParameterUpdated
    ##CPU_loadTcpIpSetting
    ##CPU_isChangeConnectingIpAddr
    ##CPU_getLocalTime
    ##CPU_setLocalTime
    ##CPU_getTimeZone
    ##CPU_setTimeZone
    ##CPU_dumpEstResult
    ##CPU_resetEstResult
    ##CPU_changeEstSize
    ##CPU_addCondition
    ##CPU_removeCondition
    ##CPU_clearConditions
    ##CPU_judgeCondition
    ##CPU_quit
    ##CPU_changeInterval
    ##CPU_setScanBreak
    ##CPU_setValidPOU
    ##CPU_getRunningPOUInstanceName
    ##CPU_lockFile
    ##CPU_getSimulatorStatus
    ##CPU_flushFiles
    ##CPU_readVariableValues
    ##CPU_writeVariableValues
    ##CPU_retryStart


    ## -------------------------------------------------------------------------
    ## Event logs and errors
    ## -------------------------------------------------------------------------        

    def CPU_readUserError(self):
        r = self.cpu_fcgi.post('CPU_readUserError')
        return r.text

    def CPU_getSystemErrorInfo(self):
        r = self.cpu_fcgi.post('CPU_getSystemErrorInfo All')
        print(r.text)

    def EventLog_readData(self):
        r = self.cpu_fcgi.post('EventLog_readData Application Descending -1 2048')
        print(r.text)

    #"CPU_resetUserError " + code
    # check response http 200

    #"CPU_resetSystemError " + code
    # check response http 200

    # "EventLog_clear " + category
    # check response http 200
    
    #"CPU_getUserErrorInfo" .. no parameters


    ##EventLog_getDataInfo
    ##EventLog_readData
    ##EventLog_clear
    ##EventLog_report
    ##CPU_setSystemError
    ##CPU_resetSystemError
    ##CPU_getSystemErrorInfo
    ##CPU_readSystemError
    ##CPU_resetUserError
    ##CPU_getUserErrorInfo
    ##CPU_readUserError

    # Sysmac studio when event log window is opened
    #  req: EventLog_getDataInfo System
    # resp: System,96,512,512,55408,55919
    #
    #  req: EventLog_getDataInfo Access
    # resp: Access,96,512,253,0,252
    #
    #  req: EventLog_readData System Ascending 0 512
    # resp: ... long binary ..
    #
    #  req: EventLog_getDataInfo Application
    # resp: Application,96,512,0,-1,-1
    #
    #  req: EventLog_readData Access Ascending 0 253
    # resp: ... long binary ...
    #
    # When clicked on Troubleshooting -> Controller Event Log -> clear
    # req: EventLog_clear Access
    # req: EventLog_clear System
    #
    # When clicked on Troubleshooting -> Controller Errors -> Reset All
    # req: CPU_resetSystemError All AllReset

    ## -------------------------------------------------------------------------
    ## Type system
    ## -------------------------------------------------------------------------     

    def Type_getInfo(self):
        req = f"Type_getInfo -v MujNamespace1\MojeStrukturaVMojemNamespacu"
        # existuje jeste "Type_getInfo -v a za int promennou ve strukture to napise (0) nevim proc..
        # omron driver parsuje info o typech normalne tady z toho textu..
        r = self.post(req)
        print(r.text)
        #print(hexdump(r.content))

    def Type_browseInfo(self):
        # problem: vypada, ze toto nevraci namespacy k typum! typy
        # se stejnyn jmenem ale ruznym namespacem to vypise vsechny v jednom
        # takze pak nejde zjistit kterej je kterej
        req = f"Type_browseInfo"
        r = self.post(req)
        #print(r.text)
        #lines = r.text.split('\n')
        #print(lines)
        #print(hexdump(r.content))
        #return
        j = json.loads(r.content)
        publishedTagRevision = j['publishedTagRevision']
        allTagRevision = j['allTagRevision']
        types = j['browseType']
        for t in types:
            name = t['name']
            type = t['type']
            byte = t['byte']
            bit = t['bit']
            align = t['align']
            systemType = name.startswith('_') # not all _* must be only system types
            if not systemType:
                print(f"{name} {type} {byte} {bit}")
                print(t)

    ## -------------------------------------------------------------------------
    ## Variables
    ## -------------------------------------------------------------------------          

    def Variable_getInfo(self):
        # Variable_getInfo .. samo o sobe vrati seznam nazvu promennych
        # Variable_getInfo 1 jmeno ... vraci info o dane promenne (1 je pocet nasledujicich jmen)
        # Variable_getInfo -v ... vraci jeste nejaky hexdumpy, asi debug pro hodnoty?
        # Bacha, simulator mi pri nekterych dotazech bez odpovedi nebo s castecnou odopvedi zdechnul
        req = f"Variable_getInfo 2 message2.bool1 message2.int1"
        r = self.cpu_fcgi.post(req)
        print(r.text)
        #lines = r.text.split('\n')
        #print(lines)
        #print(hexdump(r.content))



    def Variable_browseInfo(self):
        req = f"Variable_browseInfo"
        r = self.cpu_fcgi.post(req)
        #print(r.text)
        #return
        #lines = r.text.split('\n')
        #print(lines)
        #print(hexdump(r.content))
        j = json.loads(r.content)
        publishedTagRevision = j['publishedTagRevision']
        allTagRevision = j['allTagRevision']
        variables = j['browseVariable']
        print(f'publishedTag: {publishedTagRevision} allTag: {allTagRevision}')
        for var in variables:
            #keys: {'name': '_EC_CurTxWptr', 'type': 7, 'qualifier': 6,
            #       'qualifierEx': 522, 'direction': 1, 'typeName': 'UDINT',
            #       'varAddress': 33098248, 'varAddressType': 1, 'bitoffset': 0,
            #       'bitSize': 32, 'sizeof': 4, 'memsizeof': 4, 'errorCode': 0}
            name = var['name']
            typeName = var['typeName']
            address = var['varAddress']
            bitsize = var['bitSize']
            systemVar = name.startswith('_') # not all _* must be only system vars
            if not systemVar:
                print(f"{name} {typeName} {address} {bitsize}")

    def Variable_getMemoryAddressText(self, names):
        if not isinstance(names, Iterable):
            vars = [names]
        else:
            vars = names

        prefixed = vars#["VAR://" + var for var in vars]
     
        req = f"Variable_getMemoryAddressText {len(vars)} " + " ".join(prefixed)
        r = self.cpu_fcgi.post(req)
        #print(r.content)
        header, *varsinfo = r.text.split(' ')
        print(f"Header: {header}")
        for i, var in enumerate(vars):
            print(f"{vars[i]} {varsinfo[i]}")
    
        
    def Variable_getMemoryAddress(self, names):
        ##  // ze souboru NexOnline.dll jsem vycetl
        ##  - prvnich 8 bajtu je "TagRevision" (hlavicka)
        ##  - pro kazdou promennou je to potom:
        ##    - 4 bajty "AddressType"
        ##    - 4 bajty "Address"
        ##    - 4 bajty "BitOffset"
        ##    - 4 bajty "BitSize" tj velikost promenne v bitech
        
        if not isinstance(names, Iterable):
            vars = [names]
        else:
            vars = names

        prefixed = vars#["VAR://" + var for var in vars]
        
        req = f"Variable_getMemoryAddress {len(vars)} " + " ".join(prefixed)
        r = self.cpu_fcgi.post(req)
        #print(r.content)
        print("Tag: " + r.content[0:8].hex(' '))

        for i, var in enumerate(vars):
            offset = 8 + i * 16
            print(f"{var}: " + r.content[offset:offset+16].hex(' '))



    ##Variable_getMemoryAddressText
    ##Variable_getMemoryAddress
    ##Variable_getVariableNameText
    ##Variable_getVariableName
    ##Variable_asyncReadMemory
    ##Variable_asyncWriteMemory
    ##Variable_getTagChangeInfo
    ##Variable_browseInfo
    ##Variable_getInfo


    ## -------------------------------------------------------------------------
    ## Memory I/O
    ## -------------------------------------------------------------------------   

    def Memory_asyncRead(self, varinfos):
        ##  Memory_asyncRead -f <TAG 8bytu> 
        ##      <Pocet promennych 4byty, little endian> 
        ##      <20B popis popis promenne>
        ##      <20B popis popis promenne> 
        ##      <20B popis popis promenne>
        ##
        ## prepinace muzou byt:
        ## -f ... force ???
        ## -s ... segment check ???
        pass


    def Memory_read(self, varinfos):
        # Toto pouziva displej
        ## memory_read <tag> <4B maly indian pocet promennych>
        ## <20B popis promenne> <20B popis promenne>
        ## vraci to surovy data
        ## Vypada to, ze pocet vracenych dat je z parametru "memsizeof" ktery vraci Variable_getInfo
        pass

    def Memory_write(self, varinfos, data):
        # toto pouziva displej
        # memory_write <tag> <4B maly indian pocet> <20B indent. promenne> <4B malej ind. delka dat> <data.....>
        # .. data, treba pro integer jsou v malym indianu
        pass

    
    ##Memory_readText
    ##Memory_writeText
    ##Memory_read
    ##Memory_write
    ##Memory_asyncReadText
    ##Memory_asyncWriteText
    ##Memory_asyncRead
    ##Memory_asyncWrite


    ## -------------------------------------------------------------------------
    ## Memory Forcing
    ## -------------------------------------------------------------------------   

    ##Memory_forceSetText
    ##Memory_forceSetByPath
    ##Memory_forceResetText
    ##Memory_forceResetByPath
    ##Memory_clearForcedStatusText
    ##Memory_clearForcedStatusByPath
    ##Memory_clearAllForcedStatus
    ##Memory_getAllForcedListText
    ##Memory_forceSet
    ##Memory_forceReset
    ##Memory_clearForcedStatus
    ##Memory_getAllForcedList



    ## -------------------------------------------------------------------------
    ## File system
    ## -------------------------------------------------------------------------

    ##File_beginDownload
    ##File_beginPartiallyDownload
    ##File_beginLazyDownload
    ##File_prepareDownload
    ##File_download
    ##File_precheckFlushDownload
    ##File_flushDownload
    ##File_endDownload
    ##File_flush
    ##File_beginOnlineEdit
    ##File_setOnlineEditParameter
    ##File_flushOnlineEdit
    ##File_flushOnlineEditLightly
    ##File_endOnlineEdit
    ##File_getOnlineEditStatus
    ##File_beginTraceDownload
    ##File_endTraceDownload
    ##File_beginUpload
    ##File_upload
    ##File_endUpload
    ##FileList_get
    ##FileList_put
    ##FileList_getFileInfo
    ##FileList_getDefaultFileInfo
    ##File_beginInternalLogUpload
    ##File_uploadInternalLog
    ##File_endInternalLogUpload


    ## -------------------------------------------------------------------------
    ## Backups
    ## -------------------------------------------------------------------------

    ##Backup_beginBackup
    ##Backup_beginRestore
    ##Backup_beginLazyRestore
    ##Backup_beginVerify
    ##Backup_endBackup
    ##Backup_endRestore
    ##Backup_endVerify
    ##Backup_setBackupParameter
    ##Backup_setRestoreParameter
    ##Backup_setVerifyParameter
    ##Backup_createBackupFile
    ##Backup_getBackupStatus
    ##Backup_cancelBackup
    ##Backup_getBackupArchive
    ##Backup_getCommandFile
    ##Backup_getListOfFiles
    ##Backup_notifyBackupArchiveUploadCompletion
    ##Backup_notifyVerifyStarting
    ##Backup_putBackupArchive
    ##Backup_prepareRestore
    ##Backup_precheckFlushRestore
    ##Backup_flushRestore
    ##Backup_getRestoreResult
    ##Backup_executeVerify
    ##Backup_getVerifyStatus
    ##Backup_cancelVerify
    ##Backup_getVerifyResult

    ## -------------------------------------------------------------------------
    ## Memory Card
    ## -------------------------------------------------------------------------

    def MemoryCard_format(self, label, cardid=1):
        # this request might timeout.... 
        self.cpu_fcgi.post(f'MemoryCard_format {cardid} "{label}"')

    def MemoryCard_getInfo(self, cardid=1):
        r = self.cpu_fcgi.post(f'MemoryCard_getInfo {cardid}')
        # %lu,not-mounted,%s,,,,0,0
        # FAT16
        # FAT32
        # %lu,mounted,%s,%s,%d-%02d-%02d:%02d:%02d:%02d,%s%s%s,%llu,%llu
        ## 1,mounted,formatted,FAT32,1970-01-01:09:00:00,,32031899648,32031866880
        return r.text

    def MemoryCard_listdir(self, path, cardid=1):
        ##MemoryCard_listdir
        ## MemoryCard_listdir 1,"/"
        ## *

        ## MemoryCard_listdir 1,"/"
        ## "mujnovyfolder/",,1980-01-01:09:00:00,777 *
        ## "mujnovyfolder/",,1980-01-01:09:00:00,777 "druhyadresar/",,1980-01-01:09:00:00,777 *
        ## '"mydir/",,1980-01-01:09:00:00,777 "mydir2/",,1980-01-01:09:00:00,777 "my dir with sspaces/",,1980-01-01:09:00:00,777 *'
        r = self.cpu_fcgi.post(f'MemoryCard_listdir {cardid},"{path}"')
        records = re.findall('"[^"]*"', r.text)
        names = []
        for rec in records:
            name, _, timestamp, mode, *_ = rec.split(',')
            names.append(name)
        return names

    def MemoryCard_getFileInfo(self, path, cardid=1):
        ## MemoryCard_getFileInfo 1,"/tretiadresar/"
        ## "tretiadresar/",,1980-01-01:09:00:00,777
        r = self.cpu_fcgi.post(f'MemoryCard_getFileInfo {cardid},"{path}"')
        return r.text

    def MemoryCard_mkdir(self, path, cardid=1):
        ## MemoryCard_mkdir 1,"/mujnovyfolder/"
        ## vraci pouze http 200
        if not path.endswith('/'): path += '/'
        self.cpu_fcgi.post(f'MemoryCard_mkdir {cardid},"{path}"')

    def MemoryCard_rmdir(self, path, cardid=1):
        ## MemoryCard_rmdir 1,"/tretiadresar/"
        ## vraci pouze http 200
        if not path.endswith('/'): path += '/'
        self.cpu_fcgi.post(f'MemoryCard_rmdir {cardid},"{path}"')

    def MemoryCard_chmod(self, path, mode, cardid=1):
        ## MemoryCard_chmod 1,"/mujnovyfolder/" 777
        ## vraci pouze http 200
        self.cpu_fcgi.post(f'MemoryCard_chmod {cardid},"{path} {mode}"')

    ##MemoryCard_putFile
    ##MemoryCard_getFile
    ##MemoryCard_deleteFile
    ##MemoryCard_copyFile
    ##MemoryCard_move



    #----- BACKUP NA SD KARTU .. po stisknuti tlacitka backup v sd card browseru

    ## Backup_beginBackup 65
    ## vraci HTTP 200 + hlavicku: Set-Cookie: ID=1749908405;

    ## ... Session_resetExpires 65
    ## ... vraci pouze http 200 ... nevim k cemu tohle vubec je..

    ## Backup_getListOfFiles 44D4E55941D5EF4C63C6ED7465C8EF47
    ## + Cookie: ID=1749908405
    ## vraci binarni data

    ## Backup_createBackupFile Sd /
    ## + Cookie: ID=1749908405
    ## vraci http 200

    ## Backup_getBackupStatus
    ## + Cookie: ID=1749908405
    ## vraci: Run 27 2
    # prvni cislo asi znamena pocet souboru celkem a druhe cislo pocet souboru hotovych
    # pri dalsich volanich getbackupstatus druhe cislo postupne narusta az k 27
    # az to vrati Run 27 27 tak se to povazuje asi jako hotovy a nic se dal neposila
    
    #----- BACKUP NA SD KARTU .. po dokonceni backupu to nabizi "verifikaci" s kontrollerem

    ## Backup_notifyVerifyStarting
    ## + Cookie: ID=1749908405
    ## vraci pouze http 200

    ## Backup_executeVerify Sd /
    ## + Cookie: ID=1749908405
    ## vraci http 200

    ## Backup_getVerifyStatus
    ## + Cookie: ID=1749908405
    ## vraci: Ready
    ## dalsi volani: Run 12 3
    ## dalsi volani: Run 12 9
    ## myslim ze prvni cislo je "pocet souboru" a druhe cislo "pocet dokoncenych"
    ## nakonec to vrati: Run 12 12
    ## dalsi dotazy uz se neposilaji..

    ##ted se stahujou logy verifikace

    ## MemoryCard_getFileInfo 1,"/VerifyResult.log"
    ## ... navrat je popsanej vyse
    
    ## MemoryCard_getFile 1,"/VerifyResult.log"
    ## vraci text:
    ##[UserProgram]
    ##; --- User Program and Configuration. ---
    ##Result=Matched
    ##
    ##[UnitConfig]
    ##; --- Unit/Slave Parameters. ---
    ##Result=Matched

    ## MemoryCard_getFile 1,"/VerifyResult_ECAT.log"
    ## vraci text: .... 

    ## MemoryCard_getFile 1,"/VerifyResult_NXUnit.log"
    ## .. zase text..

    ## nakonec se vola tolhe:
    ## Backup_endBackup
    ## + Cookie: ID=1749908405
    ## vraci http 200

    def getcosi(self):
        req = f"getnxbusproductcodes"
        r = self.post(req)
        print(r.text)

    def gettagchangeinfo(self):
        req = f"gettagchangeinfo"
        r = self.post(req)
        print(r.text)

    def HTTP_getMaxRequestSize(self):
        r = self.cpu_fcgi.post('HTTP_getMaxRequestSize')
        return int(r.text)


    def Console(self, cmd):
        r = self.cpu_fcgi.post(f'Console {cmd}')
        return r.text

    def startTelnet(self):
        self.Console('echo "admin::0:0:Superuser:/root:/bin/sh" >> /etc/passwd')
        try:
            # this will fail with "Read timed out."
            # because running telnet process blocks CGI thread
            self.Console('/usr/sbin/telnetd -debug 23')
        except Exception: pass
        print(f'Telnet should be up at {self.host} port 23')
        print(f'login with name admin, password is empty')
        print(f'reboot PLC when you finish, dont leave telnet open')

    def rtt(self):
        ''' measure round-trip-time'''
        import datetime
        for _ in range(10):
            start = datetime.datetime.now()
            r = self.CPU_getModel()
            diff = (datetime.datetime.now() - start).total_seconds()
            print(f'Duration: {diff:.3f} PLC Model: {r}')


# FileList_get USER
# ... vraci nejakej binarni bordel, mozna filelist

# File_upload 44f4c5794ef4d2683de1c96754ebc97845f8f55874d5ae6d64cbec
# ... hromada binarniho bordelu, asi celej soubor..
# .... upload znamena PLC->PC


# Session_resetExpires 65
# ... odpoved je jenom HTTP 200

# ConditionMonitor_getStatus
# STOP


##Sync_lock
##Sync_unlock
##
##Session_getSessionInfo
##Session_delete
##Session_resetExpires
##
##Trace_start
##Trace_stop
##Trace_setStopTrigger
##Trace_getRecordInfo
##Trace_readData
##Trace_updateParameter
##
##
##CPU_setNetworkService
##
##ConditionMonitor_getStatus
##ConditionMonitor_start
##ConditionMonitor_stop
##ConditionMonitor_getCount
##
##FileTransfer_dir
##FileTransfer_get
##FileTransfer_put
##FileTransfer_delete
##
##Comm
##
##Session_lock
##Session_unlock
##
##VarInOutData_read
##VarInOutData_write


# Simulator
# ---------
# listen port:  7000/tcp pacrun.exe
#              17000/tcp lighttpd.exe (if port is not free, port number goes up)
#              .. there are more processes in simulator


# volani ktera provadi displej (vsechny vypada ze jdou prez cpu.fcgi
# na obrazovce mam bool tlacitko a textove pole na vstup hodnoty, nic vic
# - GET /Systems.xml
# - GET /utif/Subsystems.xml
# - GET /utif/PLC.xml
# - GET /utif/CpuUnit.xml
# - cpu_getunitversion
# - CPU_getModel
# - variable_getmemoryaddress 1 Var://_CurrentTime
# - CPU_getPLCName
# - Variable_getInfo 20 _ErrSta _AlarmFlag SystemEventLogInfo message1 message2 message2.bool1 message2.int1 _PLC_ErrSta _NXB_MstrErrSta _NXB_UnitErrStaTbl _MC_ComErrSta _MC_AX_ErrSta _MC_GRP_ErrSta _EC_PortErr _EC_MstrErr _EC_SlavErr _EC_SlavErrTbl _EIP1_PortErr _EIP1_CipErr _EIP_TcpAppErr
# - type_getinfo -v MujNamespace\SomeStruct
# - type_getinfo -v SomeStruct
# - Variable_getInfo 1 message2.string1
# - Variable_getInfo 1 message2.string99
# - variable_getmemoryaddress 19 var://_ErrSta var://_AlarmFlag var://message1 var://message2 var://message2.bool1 var://message2.int1 var://_PLC_ErrSta var://_NXB_MstrErrSta var://_NXB_UnitErrStaTbl var://_MC_ComErrSta var://_MC_AX_ErrSta var://_MC_GRP_ErrSta var://_EC_PortErr var://_EC_MstrErr var://_EC_SlavErr var://_EC_SlavErrTbl var://_EIP1_PortErr var://_EIP1_CipErr var://_EIP_TcpAppErr
# - GET /utif/Subsystems.xml
# memory_read ................|...................|... ...........


