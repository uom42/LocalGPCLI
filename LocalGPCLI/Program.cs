using System.CommandLine;

using Alba.CsConsoleFormat;
using Alba.CsConsoleFormat.Fluent;

using uom;


namespace LGPOSRPCLI;


abstract class Program
{


	[STAThread]
	static void Main (string[] args)
	{
		try
		{
			{//LOGO
				Console.WriteLine(Extensions.ConsoleSeparator);
				Console.WriteLine($"{AppInfo.Title} v{AppInfo.AssemblyFileVersionAttribute} {AppInfo.Copyright}");
				Console.WriteLine($"{AppInfo.Comments}\nThis tool don't create new SRP! Only manage existing one.");
				Console.WriteLine(Extensions.ConsoleSeparator);
			}

			if (uom.Network.Helpers.IsInDomain()) throw new NotSupportedException("This PC is in domain, use domain GPO SRP instead!");

			RegisterEnvPath();

			var cli = BuildCLI();
			cli.SetHandler(() =>
			{
				//Console.WriteLine("Main app!");
				ShowSRPStatus();
			});

			cli.InvokeCaseInsensitive(args);

		}
		catch (Exception Ex)
		{

			("ERROR: " + Ex.Message).eWriteConsole(ConsoleColor.Red);
#if DEBUG
			Ex.StackTrace.eWriteConsole(ConsoleColor.Red);
#endif
			//Console.WriteLine();
			Console.WriteLine(Extensions.ConsoleSeparator);
			Console.WriteLine($"OS: \t{uom.OS.CurrentOS.Version}");
			Console.WriteLine($"User: \t'{Environment.UserName}'");
			Console.WriteLine($"UAC elevation: \t'{uom.AppInfo.GetProcessElevation()}'");
			Console.WriteLine();
		}
		finally
		{
			/*
#if DEBUG
			"\nDEBUG MODE. Press a key to exit".eWriteConsole(ConsoleColor.Yellow);
			try
			{
				//_ = Console.ReadKey();
			}
			catch
			{
				Console.WriteLine("Can't read console input. App exited.");
			}
#endif
			 */
		}
	}

	private static void RegisterEnvPath ()
	{
#if DEBUG
		return;//Do not register debug version
#endif

		try
		{
			string[] pathVars = (Environment.GetEnvironmentVariable("path", EnvironmentVariableTarget.Machine) ?? string.Empty)
								.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

			var appDir = uom.AppInfo.AssemblyLocation.Directory!.FullName;

			if (pathVars.Any() && pathVars.eContainsInvariantCultureIgnoreCase(appDir))
			{
				//Console.WriteLine("environment Path already registered");
				return;//Already registered
			}

			pathVars = [ .. pathVars, appDir ];//Append my path to env
			string pathVar = pathVars.eJoin(Path.PathSeparator.ToString())!;
			Environment.SetEnvironmentVariable("path", pathVar, EnvironmentVariableTarget.Machine);
			//Console.WriteLine($"Registering in environment Path: '{pathVar}'");
		}
		catch (Exception ex) { }//Ignore
	}

	private static RootCommand BuildCLI ()
	{
		RootCommand rootCommand = [];
		GetCLICommands().eForEach(cmd => rootCommand.Add(cmd));
		return rootCommand;
	}
	private static Command[] GetCLICommands ()
	{
		/*

		var sub1Command = new Command("sub1", "First-level subcommand");
		rootCommand.Add(sub1Command);

		var sub1aCommand = new Command("sub1a", "Second level subcommand");
		sub1Command.Add(sub1aCommand);

		 */

		var cmdOff = new Command("off", $"Turn off SRP (set Level={nameof(SRP.LEVELS.FULLYTRUSTED)}).");
		cmdOff.SetHandler(() =>
		{
			ShowSRPStatus(false);

			//Console.WriteLine("cmdOff");
			var rSRP = new SRP(true)
			{
				Level = SRP.LEVELS.FULLYTRUSTED
			};
			AfterSRPChages(false);
			return;
		});

		var cmdOn = new Command("on", $"Turn on SRP for all users (set Level={nameof(SRP.LEVELS.DISALLOWED)}, Scope={nameof(SRP.Scope.ALL_USERS)}).");
		cmdOn.SetHandler(() =>
		{
			ShowSRPStatus(false);

			//Console.WriteLine("cmdOn");
			var rSRP = new SRP(true)
			{
				Level = SRP.LEVELS.DISALLOWED,
				Scope = SRP.SCOPES.ALL_USERS
			};
			AfterSRPChages(false);
			return;
		});

		var cmdOnExtened = new Command("onx", $"Turn on SRP for all users except Admins (set Level={nameof(SRP.LEVELS.DISALLOWED)}, Scope={nameof(SRP.Scope.ALL_EXCEPT_ADMINS)}).");
		cmdOnExtened.SetHandler(() =>
		{
			ShowSRPStatus(false);

			//Console.WriteLine("cmdOnExtened");
			var rSRP = new SRP(true)
			{
				Level = SRP.LEVELS.DISALLOWED,
				Scope = SRP.SCOPES.ALL_EXCEPT_ADMINS
			};

			AfterSRPChages(false);
			return;
		});

		Option<string> itemDataOption = new(
			name: "--path",
			description: "Path to the rule ItemData.");


		var cmdRuleAdd = new Command("rule-add", $"Create new rule for specifed path with Level={nameof(SRP.LEVELS.FULLYTRUSTED)}");
		cmdRuleAdd.AddOption(itemDataOption);
		cmdRuleAdd.SetHandler(RuleAdd, itemDataOption);

		var cmdRuleDelete = new Command("rule-delete", $"Delete rule with specifed ID.");
		Option<string> ruleIDOption = new(
			name: "--id",
			description: "Rule ID");
		cmdRuleDelete.AddOption(ruleIDOption);
		cmdRuleDelete.SetHandler(RuleDelete, ruleIDOption);


		return [ cmdOff, cmdOn, cmdOnExtened, cmdRuleAdd, cmdRuleDelete ];

	}




	private static void RuleAdd (string path)
	{
		ShowSRPStatus();

		path = path.Trim();
		if (path.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(path));

		SRP.SaferRule rule = new(path, SRP.LEVELS.FULLYTRUSTED);
		Console.WriteLine($"Creating new rule:\n{rule.ToString().eIndentLines(2, ' ')}");

		var rSRP = new SRP(true);
		rSRP.AppendRule(rule);

		AfterSRPChages(true, [ rule ]);
	}


	private static void RuleDelete (string id)
	{
		ShowSRPStatus();

		const int C_MIN_RULE_ID_LEN = 5;

		id = id.Trim();
		if (id.IsNullOrWhiteSpace() || id.Length < C_MIN_RULE_ID_LEN)
			throw new ArgumentOutOfRangeException(nameof(id), $"Rule ID '{id}' must be at least {C_MIN_RULE_ID_LEN} char len to avoid accidentally deleting important rules!");


		if (!id.Any()) throw new ArgumentNullException(nameof(id));

		var rSRP = new SRP(true);
		var allRules = rSRP.LoadRules();
		var rulesToDelete = allRules
			.Where(rule => rule.ID.ToString().Contains(id, StringComparison.OrdinalIgnoreCase))
			.ToArray();

		if (!rulesToDelete.Any())
			throw new ArgumentOutOfRangeException(nameof(id), $"Not found any rules to delete with ID contains '{id}'!");

		rSRP.Delete(rulesToDelete);
		AfterSRPChages(true);
	}


	private static void AfterSRPChages (bool showRules = true, SRP.SaferRule[]? rulesToHighLight = null)
	{
		"SRP was changed!".eWriteConsole(ConsoleColor.Yellow, ConsoleColor.DarkRed);
		ShowSRPStatus(showRules, rulesToHighLight);
	}

	static void ShowSRPStatus (bool showRules = true, SRP.SaferRule[]? rulesToHighLight = null)
	{
		Console.WriteLine("Current SRP Settings:");
		SRP srp = new(false);
		var srpString = srp.ToString().eIndentLines(2, ' ');
		Console.WriteLine(srpString);

		if (!showRules) return;

		var totalRules = srp.LoadRules();
		if (totalRules.Any())
		{
			Console.WriteLine($"SRP Rules: Total ({totalRules.Length})");

			totalRules = [ ..
				totalRules
				.OrderBy(r => r.Level)
				.ThenBy(r => r.ItemData)
				];

			var grid = new Grid
			{
				Stroke = LineThickness.Double,
				StrokeColor = ConsoleColor.DarkGray,
				AutoPosition = true,
				Align = Align.Left,
			};

			grid.Columns.Add(
				new Column { Width = GridLength.Auto },
						new Column { Width = GridLength.Auto },
						new Column { Width = GridLength.Star(1) },
						new Column { Width = GridLength.Star(1) }
					);

			//Header
			grid.Children.Add(
				new Cell("Level") { Stroke = LineThickness.Single },
				new Cell("ID") { Stroke = LineThickness.Single },
				new Cell("ItemData") { Stroke = LineThickness.Single },
				new Cell("Description") { Stroke = LineThickness.Single }
				);

			//Rows
			SRP.LEVELS oldLlevel = totalRules.First().Level;
			grid.Children.Add(
				totalRules.Select(rule =>
				{
					ConsoleColor clrText = rule.Level.ToConsoleColor();
					ConsoleColor? clrBack = null;
					if (rulesToHighLight != null && rulesToHighLight.Any())
					{
						var foundRuleToHighlight = rulesToHighLight
							.Where(r => r.ID.Equals(rule.ID))
							.Any();

						if (foundRuleToHighlight)
						{
							clrBack = ConsoleColor.Cyan;
							clrText = ConsoleColor.Magenta;
						}
					}

					var frame = LineThickness.Single;
					//var frame = new LineThickness(LineWidth.Single, LineWidth.None, LineWidth.Single, LineWidth.None); //LineThickness.Single;
					if (oldLlevel != rule.Level)
					{
						//frame.Top = LineWidth.Single;
						oldLlevel = rule.Level;
					}

					ConsoleColor clrTextPath = clrText;


					string itemData = rule.ItemData ?? string.Empty;
					if (!rule.CheckPathExist())
					{
						clrTextPath = ConsoleColor.Red;
						itemData += $"\n!PATH NOT FOUND!";
					}

					return new[]
					{
					new Cell(rule.Level) {  Stroke =   frame, Color = clrText,Background = clrBack },
					new Cell(rule.ID) { Stroke = frame, Color = clrText,Background = clrBack },
					new Cell(itemData) { Stroke = frame, Color = clrTextPath, Background = clrBack ,TextWrap = TextWrap.CharWrap  },
					new Cell(rule.Description) { Stroke = frame, Color = clrText,Background = clrBack , TextWrap = TextWrap.CharWrap },
				};
				}
				)
				);

			Colors.WriteLine(grid);
		}
	}




}

