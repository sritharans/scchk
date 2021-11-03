// Learn more about F# at https://fsharp.org

open System
open SCD.Windows

[<EntryPoint>]
let main argv =
    try
        use mySession = WMICreateSession "localhost" None None

        printfn "1. Setup the server using NTFS file system."
        GetFileSystem mySession |> Seq.iter (printfn "%A")

        printfn "2. Configure the time zone to GMT+8:00."
        GetTimeZone mySession |> Seq.iter (printfn "%s")

        printfn "3. Install the latest service pack and patches."

        GetServicePack mySession
        |> Seq.iter (printfn "%A")

        GetPatches mySession |> Seq.iter (printfn "%A")

        printfn "4. Install Antivirus software."
        //GetAV mySession |> Seq.iter (printfn "%A")

        printfn "5. Enable the screen saver password."

        GetScreenSaver mySession
        |> Seq.iter (printfn "%A")

        printfn "6. Secure the SNMP service settings."
        GetSNMP mySession |> Seq.iter (printfn "%A")
        GetReg mySession |> Array.iter (printfn "%s")

        printfn "7. Disable the Guest account."
        GetAcc mySession |> Seq.iter (printfn "%A")

        printfn "8. Configure required services only."
        GetSvcs mySession |> Seq.iter (printfn "%A")

        printfn "9. Enforce a strong password and account policy."
        GetPassPol mySession |> Seq.iter (printfn "%A")

        printfn "10. Disable all Non essential privileged accounts."

        GetPrvAcc mySession Environment.MachineName
        |> Seq.iter (printfn "%A")

    with
    | ex -> printfn "Error: %s" ex.Message

    0 // return an integer exit code
