using System.CodeDom;

namespace LGPOSRPCLI;


[TypeConverter(typeof(System.ComponentModel.ExpandableObjectConverter))]
internal partial class SRP
{

	public enum LEVELS : uint
	{
		/// <summary>Software will not run, regardless of the access rights of the user.</summary>
		DISALLOWED = 0,

		///<summary>Allows programs to execute with access only to resources granted to open well-known groups, blocking access to Administrator and Power User privileges and personally granted rights.</summary>
		UNTRUSTED = 0x1000,

		///<summary>Software cannot access certain resources, such as cryptographic keys and credentials, regardless of the access rights of the user.</summary>
		CONSTRAINED = 0x10000,

		///<summary>Allows programs to execute as a user that does not have Administrator or Power User access rights. Software can access resources accessible by normal users.</summary>
		NORMALUSER = 0x20000,

		///<summary>Software access rights are determined by the access rights of the user.</summary>
		FULLYTRUSTED = 0x40000,



	};

	public enum SCOPES : uint
	{
		ALL_USERS = 0,
		ALL_EXCEPT_ADMINS = 1
	}

	public enum SCOPE_ID : uint
	{
		///<summary>The created level is scoped by machine</summary>
		SAFER_SCOPEID_MACHINE = 1,
		///<summary>The created level is scoped by user.</summary>
		SAFER_SCOPEID_USER = 2
	}



	/// <summary>TransparentEnabled, type: dword, value: 00000002 - Defines which files to include during rule evaluation.</summary>
	public enum TRANSPARENTS : int
	{
		NONE = 0,// 0 means no enforcement, 
		NO_DLLS = 1,// 1 indicates to exclude DLLs in evaluation, 
		ALL_FILES = 2// 2 indicates to include all files in evaluation.
	}


	private const string C_KEY_ROOT = @"SOFTWARE\Policies\Microsoft\Windows";
	private const string C_SAFER_ROOT_KEY = @"SOFTWARE\Policies\Microsoft\Windows\Safer";
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



	[GeneratedRegex(@"\%(?<EnvPart>.+)\%(?<EnvSuffix>.*)")]
	private static partial Regex rxExpandable ();



	private LocalPolicy.ComputerGroupPolicyObject _localPolicy;

	public SRP (bool Writable)
	{
		var gs = new LocalPolicy.GroupPolicyObjectSettings(true, !Writable);
		_localPolicy = new LocalPolicy.ComputerGroupPolicyObject(gs);

		//Test SRP exist in GPO registry
		if (!Exist())
			throw new Exception($"GPO SRP key '{C_SAFER_CI_KEY}' was not found in GPO registry!\nLooks like the SRP policy has not been created yet.");
	}

	private bool Exist ()
	{
		var found = false;
		try
		{
			SaferOpenMachinePolicyKeyRO(C_SAFER_CI_KEY, hKeyRoot => found = true);
		}
		catch { }
		return found;
	}

	public LEVELS Level
	{
		get => (LEVELS)Safer_GetPolicyValue<int>(C_SAFER_VALUE_NAME_DefaultLevel, (int)LEVELS.FULLYTRUSTED);
		set => Safer_SetPolicyValue<int>(C_SAFER_VALUE_NAME_DefaultLevel, value.eToInt32());
	}

	public SCOPES Scope
	{
		get => (SCOPES)Safer_GetPolicyValue(C_SAFER_VALUE_NAME_PolicyScope, (int)SCOPES.ALL_USERS);
		set => Safer_SetPolicyValue<int>(C_SAFER_VALUE_NAME_PolicyScope, value.eToInt32());
	}

	///<summary>!!!Do not use env vars like '%SystemRoot%'!!!</summary>
	public string LogFileName
	{
		get => Safer_GetPolicyValue<string>(C_SAFER_VALUE_NAME_LogFileName, "");
		set => Safer_SetPolicyValue(C_SAFER_VALUE_NAME_LogFileName, value);
	}
	public bool LogFileEnabled
		=> LogFileName.IsNotNullOrWhiteSpace();


	/// <summary> Use certificates</summary>
	public bool AuthenticodeEnabled
	{
		get => (0 != Safer_GetPolicyValue<int>(C_SAFER_VALUE_NAME_AuthenticodeEnabled, 0));
		set => Safer_SetPolicyValue<bool>(C_SAFER_VALUE_NAME_AuthenticodeEnabled, value);
	}

	public TRANSPARENTS TransparentEnabled
	{
		get => (TRANSPARENTS)Safer_GetPolicyValue<int>(C_SAFER_VALUE_NAME_TransparentEnabled, (int)TRANSPARENTS.NO_DLLS);
		set => Safer_SetPolicyValue<int>(C_SAFER_VALUE_NAME_TransparentEnabled, value.eToInt32());
	}

	public string[] ExecutableTypes
	{
		get => Safer_GetPolicyValue<string[]>(C_SAFER_VALUE_NAME_ExecutableTypes, []).eSortAsArray();
		set => Safer_SetPolicyValue(C_SAFER_VALUE_NAME_ExecutableTypes, value.eSortAsArray());
	}


	private string ExecutableTypesAsFlatString
		=> ExecutableTypes.eJoin(C_EXECUTABLE_FILE_TYPES_SEPARATOR_CHAR)!;


	public override string ToString () =>
		(
		$"Level|{Level}\n" +
		$"Scope|{Scope}\n" +
		$"UseCertificates|{AuthenticodeEnabled}\n" +
		$"TransparentMode|{TransparentEnabled}\n" +
		$"LogFile|{LogFileName.EnsureNotNullOrWhiteSpace("NULL")}\n" +
		$"Executables|({ExecutableTypes.Length}): {ExecutableTypesAsFlatString}"
		).eFormatLinesAsTable(
			'|',
			": ",
			rowFinalizer: s => s.Trim()
			);




	#region Load Rules

	/*
  public void LoadGPOPathRules ()
  {
	  Clear();

	  var lRules = new List<SaferRule>();

	  Action<Microsoft.Win32.RegistryKey> KeyOpenedCallBack = hKeyCodeIdentifiers =>
	  {
		  UOMNetworkCenter.uomvb.Win32.Security.Safer.SAFER_LEVELS[] aLevels = UOMNetworkCenter.uomvb.Win32.Security.Safer.SAFER_LEVELS.SAFER_LEVELID_DISALLOWED.eGetAllValuesArray();
		  foreach (var eLevel in aLevels)
		  {
			  SaferRule[] aRulesFromLevelFolder = LoadGPOPathRules(eLevel, hKeyCodeIdentifiers);
			  if (aRulesFromLevelFolder.Any())
				  lRules.AddRange(aRulesFromLevelFolder);
		  }
	  };

	  _Parent.Policy_OpenSaferKey_Machine(C_SAFER_CI_KEY, false, KeyOpenedCallBack);

	  SaferRule[] A = (from R in lRules
					   orderby R.ItemData
					   select R).ToArray(); // Сортируем

	  AddRange(A);
  }
	 */



	private SaferRule[] LoadRules (RegistryKey keyCI)
	{
		List<SaferRule> ll = [];

		var levels = LEVELS.UNTRUSTED.eGetValues()
			.Select(e => e.eToInt32())
			.ToArray();

		foreach (var childKeyName in keyCI.GetSubKeyNames())
		{
			if (!int.TryParse(childKeyName, out var i) || !levels.Contains(i)) continue;

			var rules = LoadRules((LEVELS)i, keyCI);
			ll.AddRange(rules);
		}

		return [ .. ll ];
	}


	public SaferRule[] LoadRules ()
	{
		SaferRule[] ll = [];
		SaferOpenMachinePolicyKeyRO(C_SAFER_CI_KEY, keyCI => ll = LoadRules(keyCI));
		return [ .. ll ];
	}

	private static SaferRule[] LoadRules (LEVELS level, Microsoft.Win32.RegistryKey hKeyCodeIdentifiers)
	{
		var lRules = new List<SaferRule>();
		var hKeyLevelPath = hKeyCodeIdentifiers.OpenSubKey(level.BuildRegPath(), false);
		if (hKeyLevelPath == null) return [];

		// Есть папка с записями для этого уровня!
		using (hKeyLevelPath)
		{
			var rules = hKeyLevelPath
				.GetSubKeyNames()
				.Select(ruleGUID =>
				{
					using var hKeyGUID = hKeyLevelPath.OpenSubKey(ruleGUID, false);
					var rule = new SaferRule(hKeyGUID!)
					{
						Level = level,
						ID = new Guid(ruleGUID)
					};
					return rule;
				})
				.ToArray();

			return rules;

		}


	}


	#endregion



	public void AppendRule (SaferRule newRule)
	{
		SaferOpenMachinePolicyKey(C_SAFER_CI_KEY, true, keyCI =>
			{
				//Checking that rule for this ItemData is not exist yet
				var ruleWithSomeItemDataAlreadyExist = LoadRules(keyCI)
					.Any(ruleExist => ruleExist.ItemData?.Equals(newRule.ItemData!, StringComparison.OrdinalIgnoreCase) ?? false);

				if (ruleWithSomeItemDataAlreadyExist)
					throw new ArgumentOutOfRangeException($"Rule with ItemData='{newRule.ItemData}' already exist!");

				string rulePath = newRule.BuildRegPath();
				var hKeyRulePath = keyCI.CreateSubKey(rulePath, RegistryKeyPermissionCheck.ReadWriteSubTree);
				newRule.Write(hKeyRulePath ?? throw new System.IO.FileNotFoundException($"Failed to create key '{rulePath}'"));
				return true;
			}
		);
	}



	/*

	// Есть папка с записями для этого уровня!
	using (hKeyLevelPath)
	{
		var rules = hKeyLevelPath
			.GetSubKeyNames()
			.Select(ruleGUID =>
			{
				using var hKeyGUID = hKeyLevelPath.OpenSubKey(ruleGUID, false);
				var rule = new SaferRule(hKeyGUID!)
				{
					Level = level,
					ID = new Guid(ruleGUID)
				};
				return rule;
			})
			.ToArray();

		return rules;

	}
	 */

	#region Create / Delete

	/*
public void Delete (Microsoft.Win32.RegistryKey hKeyCodeIdentifiers)
{
		string sLevelPath = NSaferRules.BuildRegPathForLevel(Level);
		var hKeyRuleContainerPath = hKeyCodeIdentifiers.OpenSubKey(sLevelPath, true);
		if (hKeyRuleContainerPath is null)
		{
			throw new System.IO.FileNotFoundException("Отсутствует папка уровня " + sLevelPath, sLevelPath);
		}

		using (var hKeyRuleContainer = hKeyRuleContainerPath)
		{
			string sRuleID = ID.eВФигурныеСкобки().ToLower();
			hKeyRuleContainer.DeleteSubKey(sRuleID, true);
		}
}

	 */


	public void Delete (SaferRule[] rulesToDelete)
		=> SaferOpenMachinePolicyKey(C_SAFER_CI_KEY, true, keyCI => Delete(keyCI, rulesToDelete));

	private bool Delete (RegistryKey keyCI, SaferRule[] rulesToDelete)
	{
		foreach (var ruleToDelete in rulesToDelete)
		{
			string rulePath = ruleToDelete.BuildRegPath();
			keyCI.DeleteSubKeyTree(rulePath, true);
		}

		return true;

		/*
			string sLevelPath = NSaferRules.BuildRegPathForLevel(Level);
			var hKeyRuleContainerPath = hKeyCodeIdentifiers.OpenSubKey(sLevelPath, true);
			if (hKeyRuleContainerPath is null)
			{
				throw new System.IO.FileNotFoundException("Отсутствует папка уровня " + sLevelPath, sLevelPath);
			}

			using (var hKeyRuleContainer = hKeyRuleContainerPath)
			{
				string sRuleID = ID.eВФигурныеСкобки().ToLower();
				hKeyRuleContainer.DeleteSubKey(sRuleID, true);
			}
		

	}

		  */




		/*
			string sLevelPath = NSaferRules.BuildRegPathForLevel(Level);
			var hKeyRuleContainerPath = hKeyCodeIdentifiers.OpenSubKey(sLevelPath, true);
			if (hKeyRuleContainerPath is null)
			{
				throw new System.IO.FileNotFoundException("Отсутствует папка уровня " + sLevelPath, sLevelPath);
			}

			using (var hKeyRuleContainer = hKeyRuleContainerPath)
			{
				string sRuleID = ID.eВФигурныеСкобки().ToLower();
				hKeyRuleContainer.DeleteSubKey(sRuleID, true);
			}
		 */


	}

	#endregion





	public void ChangeRule (SaferRule rule)
	{
		SaferOpenMachinePolicyKey(C_SAFER_CI_KEY, true, keyCI =>
		{
			string rulePath = rule.BuildRegPath();
			var hKeyRulePath = keyCI.OpenSubKey(rulePath, Microsoft.Win32.RegistryKeyPermissionCheck.ReadWriteSubTree);
			if (hKeyRulePath == null)
				throw new System.IO.FileNotFoundException("Не удалось открыть раздел!", rulePath);

			using (hKeyRulePath)
			{
				//Write(hKeyRulePath);
			}
			return true;
		});
	}



	#region Policy Registry Helpers


	/// <summary>Callback to work with opened registry key</summary>
	/// <returns>Must return TRUE to write changes, or false</returns>
	public delegate bool OnSaferKeyOpenedRWDelegate (RegistryKey key);

	/// <summary>Callback to work with opened registry key</summary>
	/// <returns>Must return TRUE to write changes, or false</returns>
	public delegate void OnSaferKeyOpenedRODelegate (RegistryKey key);


	private void SaferOpenMachinePolicyKey (string key, bool writable, OnSaferKeyOpenedRWDelegate keyOpened)
	{
		using RegistryKey?
			hklmGPO = _localPolicy.GetRootRegistryKey(LocalPolicy.GroupPolicySection.Machine) ?? throw new System.IO.FileNotFoundException(ERR_GPO_ROOT_HKLM_FAILED_TO_OPEN),
			keySafer = hklmGPO.OpenSubKey(
				key,
				writable
				? RegistryKeyPermissionCheck.ReadWriteSubTree
				: RegistryKeyPermissionCheck.ReadSubTree)
			?? throw new System.IO.FileNotFoundException(ERR_GPO_FAILED_TO_OPEN_KEY.eFormat(key));

		var saveChanges = keyOpened!.Invoke(keySafer);
		if (writable && saveChanges)
		{
			_localPolicy.Save();
			keySafer.Flush();
		}
	}

	/// <summary>Opens Key only for ReadOnly</summary>
	/// <exception cref="System.IO.FileNotFoundException"></exception>
	private void SaferOpenMachinePolicyKeyRO (string key, OnSaferKeyOpenedRODelegate keyOpened)
	{
		SaferOpenMachinePolicyKey(key, false, key =>
		{
			keyOpened.Invoke(key);
			return false;
		}
		);
	}

	internal T Safer_GetPolicyValue<T> (string name, T defaultValue, string saferKeyPath = C_SAFER_CI_KEY)
	{
		_ = saferKeyPath ?? throw new ArgumentNullException(nameof(saferKeyPath));

		var val = defaultValue;
		SaferOpenMachinePolicyKeyRO(
			saferKeyPath,
			hKeyCodeIdentifiers => val = hKeyCodeIdentifiers.eGetValueT<T>(name, defaultValue).Value);

		return val;
	}


	internal void Safer_SetPolicyValue<T> (string name, T? newValue, string saferKeyPath = C_SAFER_CI_KEY) where T : unmanaged
	{
		_ = saferKeyPath ?? throw new ArgumentNullException(nameof(saferKeyPath));

		SaferOpenMachinePolicyKey(saferKeyPath,
			true,
			hKeyCodeIdentifiers =>
			{
				hKeyCodeIdentifiers.eSetValue<T>(name, newValue);
				return true;
			}
			);
	}

	internal void Safer_SetPolicyValue (string Name, string? newValue, string saferKeyPath = C_SAFER_CI_KEY)
	{
		_ = saferKeyPath ?? throw new ArgumentNullException(nameof(saferKeyPath));

		SaferOpenMachinePolicyKey(saferKeyPath,
			true,
			hKeyCodeIdentifiers =>
			{
				hKeyCodeIdentifiers.eSetValueString(Name, newValue);
				return true;
			}
			);
	}

	internal void Safer_SetPolicyValue (string name, string[]? newValue, string saferKeyPath = C_SAFER_CI_KEY)
	{
		_ = saferKeyPath ?? throw new ArgumentNullException(nameof(saferKeyPath));

		SaferOpenMachinePolicyKey(saferKeyPath,
			true,
			hKeyCodeIdentifiers =>
			{
				hKeyCodeIdentifiers.eSetValueStrings(name, newValue);
				return true;
			}
			);
	}

	#endregion



	[Serializable()]
	public partial class SaferRule ()
	{
		private const string C_REG_PREFIX = "%HKEY_";


		[System.Xml.Serialization.XmlAttribute]
		public Guid ID = Guid.NewGuid();

		[System.Xml.Serialization.XmlElement]
		public LEVELS Level = LEVELS.FULLYTRUSTED;

		[System.Xml.Serialization.XmlElement]
		public string? Description;

		[System.Xml.Serialization.XmlElement]
		public string? ItemData;

		[System.Xml.Serialization.XmlElement]
		public DateTime LastModified = DateTime.Now;

		[System.Xml.Serialization.XmlElement]
		public int SaferFlags = 0;

		//protected internal bool _PathExist = false;
		//protected internal string _ExpandedPath = string.Empty;


		public SaferRule (string itemData, LEVELS level) : this()
		{
			ItemData = itemData;
			Level = level;
			Description = $"Created {DateTime.Now.eToLongDateTimeString()} for '{ItemData}'";
		}

		public SaferRule (Microsoft.Win32.RegistryKey hKeyRuleGUID) : this()
		{
			Read(hKeyRuleGUID);
		}




		#region Dynamic Properties

		private bool IsExpandStringPath
			=> ItemData
				?.Trim()
				?.StartsWith(C_REG_PREFIX, StringComparison.OrdinalIgnoreCase)
				?? false;

		#endregion



		public override string ToString ()
			=> $"ID: {ID}\nItemData: '{ItemData}'\nDescription: {Description}\nLevel: {Level}\nLastModified: {LastModified}";





		public bool CheckPathExist ()
		{
			try
			{


				static string ExpandPath (string expandablePath)
				{
					/*
					%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\Temp
					%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\DefaultSpoolDirectory%
					 */

					var m = rxExpandable().Match(expandablePath);
					if (!m.Success) return expandablePath;

					var envPart = m.Groups[ "EnvPart" ].Value;
					var envSuffix = m.Groups[ "EnvSuffix" ].Value
						.eTrimStart(Path.DirectorySeparatorChar); ;

					envPart = envPart
						.Registry_GetValueAsString()
						.eTrimEnd(Path.DirectorySeparatorChar);

					var path = Path.Combine(envPart, envSuffix);
					return path;
				}

				/*
		_ExpandedPath = "";
		_ExpandedPath = GetRealPath;
				 */

				if (ItemData.IsNullOrWhiteSpace()) return true;

				var s = ItemData!.Trim();
				if (IsExpandStringPath && rxExpandable().IsMatch(s))
				{
					s = ExpandPath(s);
					if (s.IsNullOrWhiteSpace()) return false;
				}


				//TODO: Проверку на только имя файла, без пути типа runas.exe
				s = s.eTrimEnd("*")
					.eTrimEnd(Path.DirectorySeparatorChar);

				if (Path.Exists(s)) return true;

				//Path is partial
				var slashPos = s.LastIndexOf(Path.DirectorySeparatorChar);
				if (slashPos > 1)
				{
					DirectoryInfo dir = new(s[ 0..slashPos ]);
					if (dir.Exists)
					{
						var childItems = dir.GetFileSystemInfos();
						var childName = s[ (slashPos + 1).. ];

						var found = childItems.Any(x => x.Name.StartsWith(childName, StringComparison.OrdinalIgnoreCase));
						if (found) return true;
					}
				}
			}
			catch (Exception ex)
			{
				//_PathExist = false;
			}
			return false;
		}


		#region Read / Write Properties

		internal void Read (RegistryKey hKeyRuleGUID)
		{
			Description = hKeyRuleGUID.eGetValue_String("Description", "");
			ItemData = hKeyRuleGUID.eGetValue_String("ItemData", "");
			SaferFlags = (hKeyRuleGUID.eGetValue_Int32("SaferFlags", 0) ?? 0);

			long uDateTime = hKeyRuleGUID.eGetValueT("LastModified", 0L).Value;
			LastModified = uDateTime.FromGPORegDate();
		}

		internal void Write (RegistryKey hKeyRuleGUID)
		{
			var kind = IsExpandStringPath
				? RegistryValueKind.ExpandString
				: RegistryValueKind.String;

			hKeyRuleGUID!.SetValue("ItemData", ItemData ?? throw new ArgumentNullException(nameof(ItemData)), kind);

			hKeyRuleGUID.SetValue("Description", Description ?? string.Empty, Microsoft.Win32.RegistryValueKind.String);
			hKeyRuleGUID.SetValue("SaferFlags", SaferFlags, Microsoft.Win32.RegistryValueKind.DWord);

			LastModified = DateTime.Now;
			hKeyRuleGUID.SetValue("LastModified", LastModified.ToGPORegDate(), Microsoft.Win32.RegistryValueKind.QWord);

			//CheckPathExist();
		}

		#endregion


		/*
		public bool AcceptChanges (SaferRule NewRule, SRP rSafer)
		{
			bool bИзменилсяУровеньПравила = Level != NewRule.Level;

			if (!bИзменилсяУровеньПравила)
			{
				// Просто изменение некоторых свойств...
				ItemData = NewRule.ItemData;
				Description = NewRule.Description;
				LastModified = NewRule.LastModified;
				WriteProperties(rSafer);
			}

			else // Изменение уровня!!!
			{
				// Throw New NotImplementedException("Изменение уровня правила не сделано!")     
				// Надо найти старое правило и удалить его, а новое создать в новом месте!

				Action<Microsoft.Win32.RegistryKey> KeyOpenedCallBack = hKeyCodeIdentifiers =>
					{

						// Удаляем старое правило!
						Delete(hKeyCodeIdentifiers);

						// Создаём новое по новому пути
						NewRule.AddNewRuleToGPO(hKeyCodeIdentifiers);
					};

				rSafer.Policy_OpenSaferKey_Machine(C_SAFER_CI_KEY, true, KeyOpenedCallBack);

			}
			return bИзменилсяУровеньПравила;
		}

		public void UpdateLI (ListViewItem LI)
		{
			LI.eUpdateTexts(0, ItemData, Description, LastModified.ToString(), ID.ToString());

			var CLR_OK = SystemColors.Window;
			// Private Shared _RECORD_COLOR_ALLOWED As Color = Color.PaleGreen //(ARGB = 0xFF98FB98) (H; S; B; = 120; 0,9252337; 0,7901961;)
			var _RECORD_COLOR_BLOCKED = Color.LightPink; // (ARGB = 0xFFFFB6C1) (H;S;B; = 350,9589; 1; 0,8568628;)

			LI.BackColor = PathExist.IIF(CLR_OK, _RECORD_COLOR_BLOCKED);

			string sNotFind = "Не найден путь: //" + _ExpandedPath + "//";
			LI.ToolTipText = PathExist.IIF(_ExpandedPath, sNotFind);
		}

		 */






		// /// <summary> Разбирает строку вида //HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft//</summary>
		// /// <param name="sFullKeyPath">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft</param>
		// /// <param name="SUB_KEY_PATH">SOFTWARE\Microsoft</param>
		// /// <returns>HKEY_LOCAL_MACHINE</returns>
		// Private Function Registry_PathGetRoot(sFullKeyPath As String,
		// Optional ByRef SUB_KEY_PATH As String = vbNullString) As Global.Microsoft.Win32.RegistryHive

		// Dim sHKEY_ROOT = sFullKeyPath
		// SUB_KEY_PATH = vbNullString
		// Dim iFirstSlash = sHKEY_ROOT.IndexOf("\"c)                    //Ищем %HKEY_LOCAL_MACHINE\

		// If (iFirstSlash > 0) Then //Есть SUB_KEY_PATH
		// sHKEY_ROOT = sFullKeyPath.Substring(0, iFirstSlash)
		// SUB_KEY_PATH = sFullKeyPath.Substring(iFirstSlash + 1)
		// End If

		// sHKEY_ROOT = sHKEY_ROOT.ToUpper.Trim

		// Dim KeyRoot As Global.Microsoft.Win32.RegistryHive = Microsoft.Win32.RegistryHive.ClassesRoot
		// Select Case sHKEY_ROOT
		// Case "HKEY_CLASSES_ROOT" : KeyRoot = Microsoft.Win32.RegistryHive.ClassesRoot
		// Case "HKEY_CURRENT_USER" : KeyRoot = Microsoft.Win32.RegistryHive.CurrentUser
		// Case "HKEY_LOCAL_MACHINE" : KeyRoot = Microsoft.Win32.RegistryHive.LocalMachine
		// Case "HKEY_USERS" : KeyRoot = Microsoft.Win32.RegistryHive.Users
		// Case "HKEY_CURRENT_CONFIG" : KeyRoot = Microsoft.Win32.RegistryHive.CurrentConfig
		// Case Else : Throw New ArgumentException("Unknown Root Key: " & sHKEY_ROOT)
		// End Select
		// Return KeyRoot
		// End Function

		// Private Function Registry_OpenKey(sFullKeyPath As String,
		// Optional ByRef IsRoot As Boolean = False) As Global.Microsoft.Win32.RegistryKey

		// Dim sSUB_KEY = vbNullString
		// Dim RootKey = Registry_PathGetRoot(sFullKeyPath, sSUB_KEY)

		// IsRoot = sSUB_KEY.IsNullOrWhiteSpace



		// //C_REG_PREFIX
		// //Ищем первую \     

		// Return Nothing
		// End Function







		/*
		
		
		 */











	}



}


internal static class SRPExtensions
{

	internal static string BuildRegPath (this SRP.LEVELS eLevel)
		=> string.Format(@"{0}\Paths", ((int)eLevel).ToString());


	internal static string BuildRegPath (this SRP.SaferRule rule)
		=> Path.Combine(rule.Level.BuildRegPath(), rule.ID.eEncloseWithCurlyBrackets());


	#region Date Conversions

	// Тестируем преодразование времени, обратным преобразованием
	// Dim lRestored = SaferRule.ToRegDate(Me.LastModified)
	// Dim lDiff = (lRestored - uDateTime)
	// Dim I = 9I

	internal static DateTime FromGPORegDate (this long uDateTime)
		=> new DateTime(uDateTime)
			.AddYears(1600)
			.ToLocalTime();

	internal static long ToGPORegDate (this DateTime uDateTime)
		=> uDateTime
			.ToUniversalTime()
			.AddYears(-1600)
			.Ticks;


	internal static object? Registry_GetValue (this string fullRegValuePath)
	{

		//var dddd = fullRegValuePath.pathg


		var keyName = Path.GetDirectoryName(fullRegValuePath);
		var valueName = Path.GetFileName(fullRegValuePath);
		var oVal = Microsoft.Win32.Registry.GetValue(keyName, valueName, null);
		return oVal;
	}

	internal static string Registry_GetValueAsString (this string fullRegValuePath)
		=> fullRegValuePath
		.Registry_GetValue()?
		.ToString()
		?? string.Empty;

	#endregion


}
