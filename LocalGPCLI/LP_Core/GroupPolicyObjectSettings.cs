namespace LocalPolicy;


public class GroupPolicyObjectSettings (bool loadRegistryInfo = true, bool readOnly = false)
{

	public readonly bool LoadRegistryInformation = loadRegistryInfo;
	public readonly bool Readonly = readOnly;

	private const uint registryFlag = 0x00000001;
	private const uint readonlyFlag = 0x00000002;


	internal uint Flag
	{
		get
		{
			uint flag = 0x00000000;
			if (LoadRegistryInformation) flag |= registryFlag;
			if (Readonly) flag |= readonlyFlag;
			return flag;
		}
	}
}
