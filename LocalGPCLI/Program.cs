using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using uom;
using uom.Extensions;

namespace LocalGPCLI
{
    abstract class Program
    {
        private enum VALID_ARGS
        {
            Unknown,

            [Description("Turn off SRP (set Level = FULLYTRUSTED).")]
            Off,


            [Description("Turn on SRP for all users (set Level = DISALLOWED, Scope = ALL_USERS).")]
            On,


            [Description("Turn on SRP for all users except Admins (set Level = DISALLOWED, Scope = ALL_EXCEPT_ADMINS).")]
            OnExA
        }


        [STAThread]
        static void Main(string[] args)
        {
            PrintLogo();
            try
            {
                if (uom.Net.IsInDomain()) throw new NotSupportedException("This PC is in domain, use domain GPO SRP instead.");

                ShowCurrentSRPInfo();
                if (args.Any()) ParseArgs(args);
            }
            catch (Exception Ex)
            {

                ("ERROR: " + Ex.Message).e_WriteConsole(ConsoleColor.Red);
#if DEBUG
                Ex.StackTrace.e_WriteConsole(ConsoleColor.Red);
#endif
                Console.WriteLine();

                Console.WriteLine("Current OS:");
                Console.WriteLine(uom.OS.CurrentOS.ToString());
                //Console.WriteLine();
                Console.WriteLine($"User: '{uom.OS.UserAccounts.GetCurrentUserSID().LookupAccount().FQDN}'");
                Console.WriteLine($"Processs UAC elevation: '{uom.AppInfo.GetProcessElevation()}'");
                Console.WriteLine();


            }
            finally
            {
#if DEBUG
                "\nDEBUG MODE. Press a key to exit".e_WriteConsole(ConsoleColor.Yellow);
                try { _ = Console.ReadKey(); } catch { Console.WriteLine("Can't read console input. App exited."); }
#endif
            }
        }

        public static void PrintLogo()
        {
            var SeparatorStr = '-'.e_Repeat();
            Console.WriteLine(SeparatorStr);
            Console.WriteLine($"{AppInfo.Title} v{AppInfo.ProductVersion}\n{AppInfo.Copyright}");
            Console.WriteLine($"\n{AppInfo.Comments}\nIt does not allow to create new SRP, but only allow to manage existing.");

            Console.WriteLine(SeparatorStr);

            var assembly = Assembly.GetExecutingAssembly();
            var fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            var sFile = new FileInfo(assembly.Location).Name;

            Console.WriteLine("Usage:");
            foreach (VALID_ARGS a in Enum.GetValues(typeof(VALID_ARGS)))
            {
                var sDescr = a.e_GetDescriptionValue();
                if (sDescr.e_IsNOTNullOrWhiteSpace()) Console.WriteLine($"{sFile} {a.ToString()}\t= {sDescr}".e_Indent(2, ' '));
            }
            Console.WriteLine(SeparatorStr);
        }

        static void ParseArgs(string[] args)
        {
            var sFirstArg = args[0].Trim();
            var eArg = VALID_ARGS.Unknown;
            _ = Enum.TryParse<VALID_ARGS>(sFirstArg, true, out eArg);

            //var bWasChanged = false;
            switch (eArg)
            {
                case VALID_ARGS.Off:
                    {
                        var rSRP = new LGPOSRPCLI.SRP(true);
                        rSRP.Level = LGPOSRPCLI.SRP.LEVELS.FULLYTRUSTED;
                        //bWasChanged = true;
                        break;
                    }

                case VALID_ARGS.On:
                    {
                        var rSRP = new LGPOSRPCLI.SRP(true);
                        rSRP.Level = LGPOSRPCLI.SRP.LEVELS.DISALLOWED;
                        rSRP.Scope = LGPOSRPCLI.SRP.SCOPES.ALL_USERS;
                        //bWasChanged = true;
                        break;
                    }

                case VALID_ARGS.OnExA:
                    {
                        var rSRP = new LGPOSRPCLI.SRP(true);
                        rSRP.Level = LGPOSRPCLI.SRP.LEVELS.DISALLOWED;
                        rSRP.Scope = LGPOSRPCLI.SRP.SCOPES.ALL_EXCEPT_ADMINS;
                        //bWasChanged = true;
                        break;
                    }

                default:
                    throw new Exception($"Unknown argument '{sFirstArg}'!");
            }

            "\nSRP Setttings was changed!".e_WriteConsole(ConsoleColor.Green);
            ShowCurrentSRPInfo();
        }

        static void ShowCurrentSRPInfo()
        {
            Console.WriteLine("Current SRP Settings:");
            var rSRP = new LGPOSRPCLI.SRP(true);
            var sSRP = rSRP.ToString().e_Indent(2, ' ');
            Console.WriteLine(sSRP);







            /*            

            int linqCounter = 0;
            byte[] array = { 0, 0, 1, 0, 1 };
            var bytes = array.Where(x =>
            {
                linqCounter++;
                return x > 0;
            });
            bool t = bytes.First() == bytes.Last();
            Console.WriteLine(linqCounter);

             */

        }


        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        static void Test_RemoveSpaces()
        {
            const int MaxIterations = 1000000;
            string strSample = "Turn on SRP for all users except Admins (set Level = DISALLOWED, Scope = ALL_EXCEPT_ADMINS).";
            string strResult = "";

            Console.Clear();
            Console.WriteLine("Start Testing space removing from string:");
            strSample.e_WriteConsole(ConsoleColor.Green);
            Console.WriteLine($"Iterations: '{MaxIterations.e_Format()}'");

            Regex SpacesPattern = new(@"\s");

            var sw = new Stopwatch();
            sw.Start();
            for (int i = 0; i < MaxIterations; i++)
            {
                strResult = String.Empty;

                //strResult = SpacesPattern.Replace(strSample, match => string.Empty);
                //strResult = strSample.Replace(" ", string.Empty);
                strResult = string.Concat(strSample.Where(c => !char.IsWhiteSpace(c)));
            }
            sw.Stop();
            //Console.WriteLine($"Elapsed (V.Replace)= {sw.Elapsed.TotalMilliseconds}ms");
            //Console.WriteLine($"Elapsed (SpacesPattern.Replace)= {sw.Elapsed.TotalMilliseconds}ms");
            Console.WriteLine($"Elapsed (Linq.Concat)= {sw.Elapsed.TotalMilliseconds}ms");

            strResult.e_WriteConsole(ConsoleColor.Yellow);
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
