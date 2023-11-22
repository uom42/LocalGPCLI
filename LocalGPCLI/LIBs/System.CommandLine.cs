using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;


namespace System.CommandLine;

//https://stackoverflow.com/questions/79263454/c-sharp-net-system-commandline-making-the-command-line-case-insensitive/79263455#79263455
internal static class CaseInsensitiveExtensions
{

	internal static async Task<int> InvokeAsyncCaseInsensitive (this RootCommand cmdRoot, string[] args)
	{
		// Create the CommandLineBuilder with and add the Middleware
		var builder = new CommandLineBuilder(cmdRoot)
					 // Set option verb & shortcut
					 .UseVersionOption("--version", "-v")
					 .AddMiddleware(CaseInsensitiveMiddleware, MiddlewareOrder.ExceptionHandler)
					 .UseDefaults();

		var parser = builder.Build();
		return await parser.InvokeAsync(args);
	}

	internal static int InvokeCaseInsensitive (this RootCommand cmdRoot, string[] args)
	{
		// Create the CommandLineBuilder with and add the Middleware
		var builder = new CommandLineBuilder(cmdRoot)
					 // Set option verb & shortcut
					 .UseVersionOption("--version", "-v")
					 .AddMiddleware(CaseInsensitiveMiddleware, MiddlewareOrder.ExceptionHandler)
					 .UseDefaults();

		var parser = builder.Build();
		return parser.Invoke(args);
	}

	private static void CaseInsensitiveMiddleware (InvocationContext context)
	{
		//if (!CaseInsensitive) return;

		var commandOptions = context.ParseResult.CommandResult.Command.Options
									.Concat(context.ParseResult.RootCommandResult.Command.Options);

		var allAliases = commandOptions.SelectMany(option => option.Aliases);

		string[] GetCorrectTokenCase (string[] tokens)
		{
			var newTokens = new List<string>(tokens.Length);

			for (int i = 0 ; i < tokens.Length ; i++)
			{
				var token = tokens[ i ];

				var matchingAlias = allAliases.FirstOrDefault
				   (alias =>
					   alias.Equals(token, StringComparison.InvariantCultureIgnoreCase));

				if (matchingAlias != null)
				{
					newTokens.Add(matchingAlias);
					continue;
				}

				if (i > 0)
				{
					var previousToken = tokens[ i - 1 ];

					var matchingOption = commandOptions.FirstOrDefault
					   (option =>
						   option.Aliases.Contains(previousToken, StringComparer.InvariantCultureIgnoreCase));

					if (matchingOption != null)
					{
						var completions = matchingOption.GetCompletions()
														.Select(completion => completion.InsertText)
														.ToArray();

						if (completions.Length > 0)
						{
							var matchingCompletion = completions.FirstOrDefault
							   (completion =>
								   token.Equals(completion, StringComparison.InvariantCultureIgnoreCase));
							newTokens.Add(matchingCompletion ?? token);
						}
						else
						{
							newTokens.Add(token);
						}
					}
					else
					{
						newTokens.Add(token);
					}
				}
				else
				{
					newTokens.Add(token);
				}
			}

			return newTokens.ToArray();
		}

		var tokens = context.ParseResult.Tokens.Select(token => token.Value).ToArray();
		string[] newTokens;

		if (tokens.Length == 0)
		{
			newTokens = Array.Empty<string>();
		}
		else if (tokens.Length == 1)
		{
			newTokens = new[] { tokens[ 0 ].ToLowerInvariant() };
		}
		else
		{
			if (tokens[ 0 ].StartsWith("-"))
			{
				newTokens = tokens;
			}
			else
			{
				newTokens = new[] { tokens[ 0 ].ToLowerInvariant(), tokens[ 1 ].ToLowerInvariant() }
						   .Concat(GetCorrectTokenCase(tokens.Skip(2).ToArray()))
						   .ToArray();
			}
		}

		context.ParseResult = context.Parser.Parse(newTokens);
	}


}
