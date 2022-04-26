
using LocalGPCLI;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using uom;
using uom.Extensions;

namespace LGPOSRPCLI
{

    [TypeConverter(typeof(System.ComponentModel.ExpandableObjectConverter))]
    internal class SRP
    {

        public enum LEVELS : int
        {
            /// <summary>Software will not run, regardless of the access rights of the user.</summary>
            DISALLOWED = 0,

            ///<summary>Allows programs to execute as a user that does not have Administrator or Power User access rights. Software can access resources accessible by normal users.</summary>
            NORMALUSER = 0x20000,


            ///<summary>Software access rights are determined by the access rights of the user.</summary>
            FULLYTRUSTED = 0x40000,


            ///<summary>Software cannot access certain resources, such as cryptographic keys and credentials, regardless of the access rights of the user.</summary>
            CONSTRAINED = 0x10000,

            ///<summary>Allows programs to execute with access only to resources granted to open well-known groups, blocking access to Administrator and Power User privileges and personally granted rights.</summary>
            UNTRUSTED = 0x1000
        };

        public enum SCOPES : int { ALL_USERS = 0, ALL_EXCEPT_ADMINS = 1 }

        /// <summary>TransparentEnabled, type: dword, value: 00000002 - Defines which files to include during rule evaluation.</summary>
        public enum TRANSPARENTS : int
        {
            NONE = 0,// 0 means no enforcement, 
            NO_DLLS = 1,// 1 indicates to exclude DLLs in evaluation, 
            ALL_FILES = 2// 2 indicates to include all files in evaluation.
        }


        private const string C_KEY_ROOT = @"SOFTWARE\Policies\Microsoft\Windows";
        //private const string C_SAFER_ROOT_KEY = @"SOFTWARE\Policies\Microsoft\Windows\Safer";
        private const string C_SAFER_CI_KEY = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
        private const string C_SAFER_VALUE_NAME_DefaultLevel = "DefaultLevel";
        private const string C_SAFER_VALUE_NAME_PolicyScope = "PolicyScope";
        private const string C_SAFER_VALUE_NAME_LogFileName = "LogFileName";
        private const string C_SAFER_VALUE_NAME_ExecutableTypes = "ExecutableTypes";
        private const string C_SAFER_VALUE_NAME_AuthenticodeEnabled = "AuthenticodeEnabled";
        private const string C_SAFER_VALUE_NAME_TransparentEnabled = "TransparentEnabled";

        private const string C_EXECUTABLE_FILE_TYPES_SEPARATOR_CHAR = ",";

        private const string ERR_GPO_ROOT_HKLM_FAILED_TO_OPEN = "Failed to open root GPO HKLM!";
        private const string ERR_GPO_FAILED_TO_OPEN_KEY = "Failed to open GPO key '{0}'!";

        LocalPolicy.ComputerGroupPolicyObject _LocalPol;

        public SRP(bool Writable)
        {
            var S = new LocalPolicy.GroupPolicyObjectSettings(true, !Writable);
            _LocalPol = new LocalPolicy.ComputerGroupPolicyObject(S);

            //Test SRP exist in GPO registry
            if (!exist())
                throw new Exception($"The GPO SRP key '{C_SAFER_CI_KEY}' is not found in GPO registry! It looks like the SRP policy has not been created yet.");
        }

        private Boolean exist()
        {
            var bFound = false;
            //Trying to open safer GPO key
            try { Policy_OpenSaferKey_Machine(C_SAFER_CI_KEY, false, hKeyRoot => { bFound = true; }); } catch { }
            return bFound;
        }
        static Boolean Exist()
        {
            try
            {
                var rSRPInst = new SRP(false);
                return true;
            }
            catch { }
            return false;
        }



        public LEVELS Level
        {
            get => Policy_GetSaferValue(C_SAFER_VALUE_NAME_DefaultLevel, LEVELS.FULLYTRUSTED);
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_DefaultLevel, (Int32)value, DeleteRegistryValueIfNullValue: false);
        }

        public SCOPES Scope
        {
            get => Policy_GetSaferValue(C_SAFER_VALUE_NAME_PolicyScope, SCOPES.ALL_USERS);
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_PolicyScope, (Int32)value, DeleteRegistryValueIfNullValue: false);
        }

        ///<summary>!!!Do not use env vars like '%SystemRoot%'!!!</summary>
        public string LogFileName
        {
            get => Policy_GetSaferValue<String>(C_SAFER_VALUE_NAME_LogFileName, "");
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_LogFileName, value, RegistryValueKind.String, DeleteRegistryValueIfNullValue: false);
        }
        public Boolean LogFileEnabled { get => LogFileName.e_IsNOTNullOrWhiteSpace(); }

        /// <summary> Use certificates</summary>
        public Boolean AuthenticodeEnabled
        {
            get => (1 == Policy_GetSaferValue(C_SAFER_VALUE_NAME_AuthenticodeEnabled, 0));
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_AuthenticodeEnabled, value.e_ToInt32ABS(), DeleteRegistryValueIfNullValue: false);
        }

        public TRANSPARENTS TransparentEnabled
        {
            get => Policy_GetSaferValue(C_SAFER_VALUE_NAME_TransparentEnabled, TRANSPARENTS.NO_DLLS);
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_TransparentEnabled, (Int32)value, DeleteRegistryValueIfNullValue: false);
        }

        public String[] ExecutableTypes
        {
            get => Policy_GetSaferValue<String[]>(C_SAFER_VALUE_NAME_ExecutableTypes, new String[] { }).e_Sort();
            set => Policy_SetSaferValue(C_SAFER_VALUE_NAME_ExecutableTypes, value.e_Sort(), RegistryValueKind.MultiString, DeleteRegistryValueIfNullValue: false);
        }

        public string ExecutableTypesAsFlatString => ExecutableTypes.e_Join(C_EXECUTABLE_FILE_TYPES_SEPARATOR_CHAR)!;

        public override string ToString() =>
            $"Level: {Level}\n" +
            $"Scope: {Scope}\n" +
            $"Use certificates: {AuthenticodeEnabled}\n" +
            $"Transparent mode: {TransparentEnabled}\n" +
            $"Log File: {LogFileName.e_ToStringAllowNull()}\n" +
            $"Executables ({ExecutableTypes.Length}): {ExecutableTypesAsFlatString}";

        private void Policy_OpenSaferKey_Machine(String Key, Boolean Writable, Action<RegistryKey> KeyOpenedCallBack)
        {
            using (var HKLM_GPO = _LocalPol.GetRootRegistryKey(LocalPolicy.GroupPolicySection.Machine))
            {
                if (HKLM_GPO == null) throw new System.IO.FileNotFoundException(ERR_GPO_ROOT_HKLM_FAILED_TO_OPEN);
                using (var hKeySafer = HKLM_GPO.OpenSubKey(Key, Writable ? RegistryKeyPermissionCheck.ReadWriteSubTree : RegistryKeyPermissionCheck.ReadSubTree))
                {
                    _ = hKeySafer ?? throw new System.IO.FileNotFoundException(ERR_GPO_FAILED_TO_OPEN_KEY.e_Format(Key));
                    KeyOpenedCallBack.Invoke(hKeySafer);
                    if (Writable)
                    {
                        _LocalPol.Save();
                        hKeySafer.Flush();
                    }
                }
            }
        }

        internal T Policy_GetSaferValue<T>(String Name, T DefaultValue, string SaferKeyPath = C_SAFER_CI_KEY)
        {
            _ = SaferKeyPath ?? throw new ArgumentNullException(nameof(SaferKeyPath));
            var tVal = DefaultValue;
            Policy_OpenSaferKey_Machine(SaferKeyPath,
                false,
                hKeyCodeIdentifiers => tVal = hKeyCodeIdentifiers.e_GetValueT<T>(Name, DefaultValue).Value);
            return tVal;
        }


        internal void Policy_SetSaferValue(String Name,
            Object oValue,
            RegistryValueKind Kind = RegistryValueKind.DWord,
            string SaferKeyPath = C_SAFER_CI_KEY,
            Boolean DeleteRegistryValueIfNullValue = true)
        {
            _ = SaferKeyPath ?? throw new ArgumentNullException(nameof(SaferKeyPath));

            Policy_OpenSaferKey_Machine(SaferKeyPath,
                true,
                hKeyCodeIdentifiers => hKeyCodeIdentifiers.e_SetValue(Name, oValue, Kind, DeleteRegistryValueIfNullValue));
        }


















        private const uint S_OK = 0;
        protected static void trycatch(Func<uint> operation, string messageTemplate, params object[] messageArgs)
        {
            uint result = operation();
            if (result != S_OK)
            {
                string message = string.Format(messageTemplate, messageArgs);
                throw new Exception(string.Format("{0}. Error code {1} (see WinError.h)", message, result));
            }
        }
        protected string getString(Func<StringBuilder, int, uint> func, string errorMessage)
        {
            StringBuilder sb = new StringBuilder();
            //trycatch(() => func(sb, maxLength), errorMessage);
            return sb.ToString();
        }
    }
}
