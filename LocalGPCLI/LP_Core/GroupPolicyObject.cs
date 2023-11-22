namespace LocalPolicy;


public abstract class GroupPolicyObject
{
	private const uint S_OK = 0;
	protected const int maxLength = 1024;

	/// <summary> The snap-in that processes .pol files </summary>
	private static readonly Guid RegistryExtension = new(0x35378EAC, 0x683F, 0x11D2, 0xA8, 0x9A, 0x00, 0xC0, 0x4F, 0xBB, 0xCF, 0xA2);

	/// <summary>This application 
	/// 
	/// .cproj must contains:
	///  <ItemGroup>
	/// 		<!-- This GUID Used for COM Group Policy app identification
	/// 		Include must be the fully qualified.NET type name of the Attribute to create. -->
	/// 		<AssemblyAttribute Include = "System.Runtime.InteropServices.GuidAttribute" >
	/// 			< !--_Parameter1, _Parameter2, etc.correspond to the matching parameter of a constructor of that .NET attribute type -->
	/// 			<_Parameter1>37d9d706-7a9e-4a50-974f-bc13bd0b9d27</_Parameter1>
	/// 		</AssemblyAttribute>
	/// 	</ItemGroup>
	/// 	
	/// 
	/// </summary>
	private static readonly Guid LocalGuid = new(uom.AppInfo.GetAssemblyAttribute<GuidAttribute>()!.Value);

	protected LocalPolicy.COM.IGroupPolicyObject? instance = null;

	internal GroupPolicyObject ()
		=> instance = getInstance();

	/// <summary> Saves the specified registry policy settings to disk and updates the revision number of the GPO. This saves both machine and user level settings. </summary>
	public void Save ()
	{
		trycatch(() => instance!.Save(true, true, RegistryExtension, LocalGuid), "Error saving machine settings");
		trycatch(() => instance!.Save(false, true, RegistryExtension, LocalGuid), "Error saving user settings");
	}

	/// <summary>
	/// Deletes the GPO. You should not invoke any methods on this object after calling Delete. 
	/// </summary>
	public void Delete ()
	{
		trycatch(() => instance!.Delete(), "Error deleting the GPO");
		instance = null;
	}

	/// <summary>The unique GPO name.
	/// For a local GPO, this will be "Local".
	/// For remote objects, this will be the computer name.
	/// For Active Directory policy objects, this will be a GUID.</summary>
	public string UniqueName
		=> getString(instance!.GetName, "Unable to retrieve name");

	/// <summary>The display name for the GPO.</summary>
	public string DisplayName
	{
		get => getString(instance!.GetDisplayName, "Unable to retrieve display name");
		set => trycatch(() => instance!.SetDisplayName(value), "Unable set display name to {0}", value);
	}

	/// <summary> Retrieves the path to the GPO. 
	/// If the GPO is an Active Directory object, the path is in ADSI name format. 
	/// If the GPO is a computer object, this parameter receives a file system path. </summary>
	public string Path
		=> getString(instance!.GetPath, "Unable to retrieve path");


	/// <summary> Retrieves the root of the registry key for the specified GPO section </summary>
	public RegistryKey GetRootRegistryKey (GroupPolicySection section)
	{
		IntPtr key = default(IntPtr);
		trycatch(() => instance!.GetRegistryKey((uint)section, out key), "Unable to get section '{0}'", Enum.GetName(typeof(GroupPolicySection), section));
		var safeHandle = new SafeRegistryHandle(key, true);
		return RegistryKey.FromHandle(safeHandle);
	}

	/// <summary> Options that determine which parts of the GPO are enabled. </summary>
	public GroupPolicyObjectOptions Options
	{
		get
		{
			uint flag = 0;
			trycatch(() => instance!.GetOptions(out flag), "Unable to retrieve options");
			return new GroupPolicyObjectOptions(flag);
		}
		set => trycatch(() => instance!.SetOptions(value.Flag, GroupPolicyObjectOptions.Mask), "Unable to set options");
	}


	public abstract string GetPathTo (GroupPolicySection section);


	protected static LocalPolicy.COM.IGroupPolicyObject getInstance ()
	{
		return withSingleThreadedApartmentCheck(() =>
		{
			LocalPolicy.COM.GPClass concrete = new();
			return (LocalPolicy.COM.IGroupPolicyObject)concrete;
		});
	}





	protected static T withSingleThreadedApartmentCheck<T> (Func<T> operation)
	{
		try { return operation(); }
		catch (InvalidCastException e)
		{
			if (System.Threading.Thread.CurrentThread.GetApartmentState() != System.Threading.ApartmentState.STA)
				throw new RequiresSingleThreadedApartmentException(e);

			else throw e;
		}
	}



	protected static void trycatch (Func<uint> operation, string messageTemplate, params object[] messageArgs)
	{
		uint result = operation();
		if (result != S_OK)
		{
			string message = string.Format(messageTemplate, messageArgs);
			throw new GroupPolicyException($"{message}. Error code {result} (see WinError.h)");
		}
	}


	protected string getString (Func<StringBuilder, int, uint> func, string errorMessage)
	{
		StringBuilder sb = new();
		trycatch(() => func(sb, maxLength), errorMessage);
		return sb.ToString();
	}
}
