using System;
using System.Diagnostics;

namespace ProcessThis
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch watch = new Stopwatch { };
            watch.Start();
            ListProcesses();
            watch.Stop();
            string seconds = (watch.ElapsedMilliseconds / 1000).ToString();
            Console.WriteLine("[*] Completed in {0} seconds", seconds);
        }

        static void ListProcesses()
        {
            // Many of these were the drivers from https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna
            // Unlikely that the process names will match but they were added here for extra coverage
            string[] EDRProcessNames = new string[]
                {
                   "acdriver",
                   "amfsm",
                   "amm6460",
                   "amm8660",
                   "aswsp",
                   "atc",
                   "atrsdfw",
                   "avc3",
                   "avckf",
                   "avgtpx64",
                   "avgtpx86",
                   "bddevflt",
                   "bdsandbox",
                   "bdsvm",
                   "bhdrvx64",
                   "bhdrvx86",
                   "brcow_x_x_x_x",
                   "brfilter",
                   "carbonblackk",
                   "cb",
                   "cbk7",
                   "cbstream",
                   "ccsvchst",
                   "cfrmd",
                   "cmdccav",
                   "cmdguard",
                   "cmdmnefs",
                   "cposfw",
                   "crexecprev",
                   "csaam",
                   "csaav",
                   "csacentr",
                   "csaenh",
                   "csagent",
                   "csareg",
                   "csascr",
                   "csfalconcontainer",
                   "csfalconservice",
                   "cve",
                   "cybkerneltracker",
                   "cylancesvc",
                   "cylanceui",
                   "cyoptics",
                   "cyprotectdrv32",
                   "cyprotectdrv64",
                   "dgdmk",
                   "diflt",
                   "dsfa",
                   "eaw",
                   "edevmon",
                   "edrsensor",
                   "ehdrv",
                   "emxdrv2",
                   "epdrv",
                   "epregflt",
                   "esensor",
                   "evmf",
                   "fekern",
                   "fencry",
                   "fileflt",
                   "fsatp",
                   "fsgk",
                   "fshs",
                   "gefcmp",
                   "geprotection",
                   "groundling32",
                   "groundling64",
                   "gzflt",
                   "hbflt",
                   "hdlpflt",
                   "hexisfsmonitor",
                   "hfileflt",
                   "im",
                   "klifaa",
                   "klifks",
                   "klifsm",
                   "libwamf",
                   "lragentmf",
                   "mbamwatchdog",
                   "medlpflt",
                   "mfeaskm",
                   "mfeeeff",
                   "mfehidk",
                   "mfencfilter",
                   "mfencoas",
                   "mfprom",
                   "msmpeng",
                   "mydlpmf",
                   "parity",
                   "pgpfs",
                   "pgpwdefs",
                   "psepfilter",
                   "psinfile",
                   "psinproc",
                   "reghook",
                   "repux",
                   "rvsavd",
                   "safe-agent",
                   "sakfile",
                   "sakmfile",
                   "savonaccess",
                   "sentinelmonitor",
                   "sisipsfilefilter",
                   "sld",
                   "smc",
                   "snac",
                   "spbbcdrv",
                   "ssfmonm",
                   "ssrfsf",
                   "swin",
                   "symafr",
                   "symefa",
                   "symefa64",
                   "symefasi",
                   "symevent",
                   "symhsm",
                   "symrg",
                   "sysmon",
                   "taniumclient",
                   "tmesflt",
                   "tmevtmgr",
                   "tmfileencdmk",
                   "tmumh",
                   "tmums",
                   "trufos",
                   "vfsenc",
                   "virtfile",
                   "virtualagent",
                   "vxfsrep",
                   "wfp_mrt",
                   "xagt"
                };
            var processes = Process.GetProcesses();
            Console.WriteLine("[*] Analyzing names for {0} processes...", processes.Length.ToString());
            foreach (var process in processes)
            {
                foreach (string EDRProcessName in EDRProcessNames)
                {
                    if (process.ProcessName.ToLower() == EDRProcessName)
                    {
                        Console.WriteLine("[!] Found AV/EDR process: {0} (PID: {1})", process.ProcessName, process.Id.ToString());
                    }
                }
                
            }
            return;
        }
    }
}
