﻿namespace LocalPolicy;


public class ComputerGroupPolicyObject : GroupPolicyObject
{


	/// <summary>Returns true if the object is on the local machine</summary>
	public readonly bool IsLocal;


	/// <summary>Opens the default GPO for the local computer </summary>
	public ComputerGroupPolicyObject (GroupPolicyObjectSettings? options = null)
	{
		options ??= new GroupPolicyObjectSettings();
		trycatch(() => instance!.OpenLocalMachineGPO(options!.Flag), "Unable to open local machine GPO");
		IsLocal = true;
	}


	/// <summary>Opens the default GPO for the specified remote computer</summary>
	/// <param name="computerName">Name of the remote computer in the format "\\ComputerName"</param>
	public ComputerGroupPolicyObject (string computerName, GroupPolicyObjectSettings? options = null)
	{
		options ??= new GroupPolicyObjectSettings();
		trycatch(() => instance!.OpenRemoteMachineGPO(
			computerName,
			options!.Flag),
			$"Unable to open GPO on remote machine '{computerName}'");

		IsLocal = false;
	}


	/// <summary>Returns true if the object is on a remote machine. Use ComputerName to find out the name of that machine.</summary>
	public bool IsRemote => !IsLocal;

	/// <summary>Returns the name of the machine on which the GPO resides. Returns "Local" if is on the local machine. </summary>
	public string ComputerName => UniqueName;


	/// <summary> Retrieves the file system path to the root of the specified GPO section. The path is in UNC format. </summary>
	public override string GetPathTo (GroupPolicySection section)
	{
		StringBuilder sb = new(maxLength);
		trycatch(() => instance!.GetFileSysPath(
			(uint)section,
			sb,
			maxLength),
			$"Unable to retrieve path to section '{Enum.GetName(typeof(GroupPolicySection), section)}'");
		return sb.ToString();
	}
}
