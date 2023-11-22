namespace LGPOSRPCLI;


internal static class Extensions
{

	public static string ConsoleSeparator
		=> '-'.eRepeat();



	public static ConsoleColor ToConsoleColor (this LGPOSRPCLI.SRP.LEVELS level)
		=> level switch
		{
			SRP.LEVELS.DISALLOWED => ConsoleColor.Blue,

			///<summary>Allows programs to execute with access only to resources granted to open well-known groups, blocking access to Administrator and Power User privileges and personally granted rights.</summary>
			SRP.LEVELS.UNTRUSTED => ConsoleColor.DarkYellow,

			///<summary>Software cannot access certain resources, such as cryptographic keys and credentials, regardless of the access rights of the user.</summary>
			SRP.LEVELS.CONSTRAINED => ConsoleColor.Yellow,

			///<summary>Allows programs to execute as a user that does not have Administrator or Power User access rights. Software can access resources accessible by normal users.</summary>
			SRP.LEVELS.NORMALUSER => ConsoleColor.DarkGreen,

			///<summary>Software access rights are determined by the access rights of the user.</summary>
			SRP.LEVELS.FULLYTRUSTED => ConsoleColor.Green,
			_ => throw new ArgumentOutOfRangeException(nameof(level))
		};

}
