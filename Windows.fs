module SCD.Windows

open System
open System.Globalization

open Microsoft.Management.Infrastructure
open Microsoft.Management.Infrastructure.Options

type Hive =
    | HKCR = 2147483648u // HKEY_CLASSES_ROOT
    | HKCU = 2147483649u // HKEY_CURRENT_USER
    | HKLM = 2147483650u // HKEY_LOCAL_MACHINE
    | HKUS = 2147483651u // HKEY_USERS
    | HKCC = 2147483653u // HKEY_CURRENT_CONFIG

type DateInput =
    | DateStr of CimInstance * string
    | FormatDateStr of CimInstance * string * string

// Root WMI namespace
let wmiNameSpace = @"Root\CIMV2"
// Root Group Policy namespace
let rsopNameSpace = @"Root\RSOP\Computer"
// Default NaN constant
let defaultNaN = "N/A"

// Create a WMI session for the target host
let WMICreateSession hostname username password =
    match username, password with
    | Some user, Some pass ->
        use sessionOptions = new WSManSessionOptions()
        use securepass = new Security.SecureString()
        String.iter securepass.AppendChar pass

        let cimCredential =
            CimCredential(PasswordAuthenticationMechanism.Default, hostname, user, securepass)

        sessionOptions.AddDestinationCredentials(cimCredential)
        CimSession.Create(hostname, sessionOptions)
    | _ ->
        use sessionOptions = new DComSessionOptions()
        sessionOptions.Timeout <- TimeSpan.FromSeconds 30.0
        CimSession.Create(hostname, sessionOptions)

let GetStr (instance: CimInstance) property =
    let items = instance.CimInstanceProperties

    match isNull items.[property] with
    | false when not (isNull items.[property].Value) -> items.[property].Value.ToString()
    | _ -> defaultNaN

let GetDate dateinput =
    match dateinput with
    | DateStr (instance, property) ->
        let items = instance.CimInstanceProperties

        match isNull items.[property] with
        | false when not (isNull items.[property].Value) ->
            DateTime
                .Parse(items.[property].Value.ToString(), CultureInfo.InvariantCulture)
                .ToShortDateString()
        | _ -> defaultNaN
    | FormatDateStr (instance, property, format) ->
        let items = instance.CimInstanceProperties

        match isNull items.[property] with
        | false when not (isNull items.[property].Value) ->
            DateTime
                .ParseExact(items.[property].Value.ToString(), format, CultureInfo.InvariantCulture)
                .ToShortDateString()
        | _ -> defaultNaN

// 1. Setup the server using NTFS file system.
let GetFileSystem (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_LogicalDisk")
    |> Seq.map (fun x -> GetStr x "DeviceID", GetStr x "FileSystem")

// 2. Configure the time zone.
let GetTimeZone (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_TimeZone")
    |> Seq.map (fun x -> GetStr x "Caption")

// 3. Install the latest service pack and patches.
let GetServicePack (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_OperatingSystem")
    |> Seq.map (fun x ->
        GetStr x "Caption",
        GetStr x "ServicePackMajorVersion"
        + "."
        + GetStr x "ServicePackMinorVersion",
        GetStr x "Version")

let GetPatches (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_QuickFixEngineering")
    |> Seq.map (fun x -> GetStr x "HotFixID", GetDate(DateStr(x, "InstalledOn")))

// 4. Install Antivirus software.
let GetAV (wmisession: CimSession) =
    wmisession.QueryInstances(
        wmiNameSpace,
        "WQL",
        "SELECT * FROM Win32Reg_AddRemovePrograms WHERE Publisher='Trend Micro Inc.'"
    )
    |> Seq.map (fun x ->
        GetStr x "DisplayName", GetStr x "Version", GetDate(FormatDateStr(x, "InstallDate", "yyyyMMdd")))

// 5. Enable the screen saver password.
let GetScreenSaver (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_Desktop")
    |> Seq.map (fun x ->
        GetStr x "Name", GetStr x "ScreenSaverActive", GetStr x "ScreenSaverSecure", GetStr x "ScreenSaverTimeout")

// 6. Secure the SNMP service settings [If SNMP is installed or enabled]
let GetSNMP (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_OptionalFeature WHERE Name LIKE '%SNMP%'")
    |> Seq.map (fun x -> GetStr x "Caption", GetStr x "Status", GetStr x "InstallState", GetStr x "InstallDate")

let GetReg (wmisession: CimSession) =
    use cimParams = new CimMethodParametersCollection()
    cimParams.Add(CimMethodParameter.Create("hDefKey", Hive.HKLM, CimType.UInt32, CimFlags.In))

    cimParams.Add(
        CimMethodParameter.Create(
            "sSubKeyName",
            "SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities",
            CimFlags.In
        )
    )

    use enumValues =
        wmisession.InvokeMethod(wmiNameSpace, "StdRegProv", "EnumValues", cimParams)

    match isNull enumValues.OutParameters.["sNames"].Value with
    | false -> enumValues.OutParameters.["sNames"].Value :?> String []
    | _ -> [| defaultNaN |]

// 7. Disable the Guest account.
let GetAcc (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_UserAccount WHERE LocalAccount=TRUE")
    |> Seq.map (fun x -> GetStr x "Name", GetStr x "Disabled")

// 8. Configure required services only.
let GetSvcs (wmisession: CimSession) =
    wmisession.QueryInstances(wmiNameSpace, "WQL", "SELECT * FROM Win32_Service")
    |> Seq.map (fun x -> GetStr x "Caption", GetStr x "State", GetStr x "StartMode", GetStr x "StartName")

// 9. Enforce a strong password and account policy.
let GetPassPol (wmisession: CimSession) =
    wmisession.QueryInstances(rsopNameSpace, "WQL", "SELECT * FROM RSOP_SecuritySettings")
    |> Seq.map (fun x -> GetStr x "LockoutDuration")

// 10. Disable all Non essential privileged accounts.
// ASSOCIATORS OF {Win32_Group,Name='Administrators'} WHERE ResultClass = Win32_UserAccount
let GetPrvAcc (wmisession: CimSession) hostname =
    wmisession.QueryInstances(
        wmiNameSpace,
        "WQL",
        "ASSOCIATORS OF {Win32_Group.Domain='"
        + hostname
        + "',Name='Administrators'} WHERE Role=GroupComponent"
    )
    |> Seq.map (fun x -> GetStr x "Name", GetStr x "Domain")
