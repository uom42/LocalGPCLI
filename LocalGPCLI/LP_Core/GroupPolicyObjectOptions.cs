namespace LocalPolicy;


public struct GroupPolicyObjectOptions (bool userEnabled = true, bool machineEnabled = true)
{
	private const uint disableUserFlag = 0x00000001;
	private const uint disableMachineFlag = 0x00000002;
	internal const uint Mask = disableUserFlag | disableMachineFlag;

	public readonly bool UserEnabled = userEnabled;
	public readonly bool MachineEnabled = machineEnabled;


	public GroupPolicyObjectOptions (uint flag) : this(
		(flag & disableUserFlag) == 0,
		(flag & disableMachineFlag) == 0
		)
	{ }

	internal uint Flag
	{
		get
		{
			uint flag = 0;
			if (!UserEnabled) flag |= disableUserFlag;
			if (!MachineEnabled) flag |= disableMachineFlag;
			return flag;
		}
	}

}
