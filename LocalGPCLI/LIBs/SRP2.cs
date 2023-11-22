using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;


namespace LGPOSRPCLI;


class _failedMemberConversionMarker1
{
	/* Cannot convert MethodStatementSyntax, System.ArgumentOutOfRangeException: Specified argument was out of the range of valid values.
	#error Cannot convert MethodBlockSyntax - see comment for details
	Parameter name: member
	   at ICSharpCode.CodeConverter.CSharp.DeclarationNodeVisitor.GetMemberContext(StatementSyntax member)
	   at ICSharpCode.CodeConverter.CSharp.DeclarationNodeVisitor.<VisitMethodStatement>d__83.MoveNext()
	--- End of stack trace from previous location where exception was thrown ---
	   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()
	   at ICSharpCode.CodeConverter.CSharp.CommentConvertingVisitorWrapper.<ConvertHandledAsync>d__12`1.MoveNext()

	Input: 


	#Region "Safer Rules"

	Public Function ReadGPORules() As Global.UOMNetworkCenter.NSaferRules

	Context:



	#Region "Safer Rules"

	Public Function ReadGPORules() As Global.UOMNetworkCenter.NSaferRules
		Dim NNN As New Global.UOMNetworkCenter.NSaferRules(Me)
		Call NNN.LoadGPOPathRules()
		Return NNN
	End Function

	 */
}

/*
[Serializable()]
public class NSaferRules : List<SaferRule>
{

	protected SRP _Parent = default;
	public NSaferRules (SRP rParent) : base()
	{
		_Parent = rParent;
	}

	public static string BuildRegPathForLevel (UOMNetworkCenter.uomvb.Win32.Security.Safer.SAFER_LEVELS eLevel)
	{
		string sRulePath = string.Format(@"{0}\Paths", ((int)eLevel).ToString());
		return sRulePath;
	}

	#region LoadGPORules

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


	internal static SaferRule[] LoadGPOPathRules (UOMNetworkCenter.uomvb.Win32.Security.Safer.SAFER_LEVELS eLevel, Microsoft.Win32.RegistryKey hKeyCodeIdentifiers)
	{

		string sLevelKey = BuildRegPathForLevel(eLevel);
		var lRules = new List<SaferRule>();

		var hKeyLevelPath = hKeyCodeIdentifiers.OpenSubKey(sLevelKey, false);
		if (hKeyLevelPath is not null)
		{
			// Есть папка с записями для этого уровня!
			using (var hKeyLevel = hKeyLevelPath)
			{
				string[] aGUIDDirs = hKeyLevel.GetSubKeyNames();

				foreach (var sGUID in aGUIDDirs)
				{
					using (var hKeyGUID = hKeyLevel.OpenSubKey(sGUID, false))
					{
						var SR = new SaferRule(hKeyGUID) { Level = eLevel, ID = new Guid(sGUID) };
						lRules.Add(SR);
					}
				}

			}
		}

		return lRules.ToArray();
	}
	#endregion



	public SaferRule FindRule (Guid ID)
	{
		foreach (var R in this)
		{
			if (R.ID.Equals(ID))
				return R;
		}
		return null;
	}

	public new void Add (SaferRule NewRule)
	{
		var rOldRule = FindRule(NewRule.ID);
		bool bRuleAlreadyExist = rOldRule is not null;

		if (bRuleAlreadyExist)
		{
			// НА БУДУЩЕЕ - надо найти и исправить параметры существующего правила, с загружаемого
			// Dim rOldRule = _SaferRules.GetRuleByID(rRuleToImport.ID)
			// Dim bRuleAlreadyExist = (rOldRule IsNot Nothing)
			// If Not bRuleAlreadyExist Then
			// Правила ещё нет, добавляем
			// Call _SaferRules.Add(rRuleToImport)
			// End If




			string S = string.Format("Правило с таким ID уже существует в Local GPO!||Существующее правило:|{0}||Загружаемое правило:|{1}", rOldRule.ToString(), NewRule.ToString()).eWrap();

			throw new Exception(S);
		}


		// Правила с таким ID ещё нет! - Создаём новое!
		NewRule.AddNewRuleToGPO(_Parent);

	}

	public void KillRules (SaferRule[] aRulesToKill)
	{

		Action<Microsoft.Win32.RegistryKey> KeyOpenedCallBack = hKeyCodeIdentifiers => { foreach (var RRR in aRulesToKill) RRR.Delete(hKeyCodeIdentifiers); };

		_Parent.Policy_OpenSaferKey_Machine(C_SAFER_CI_KEY, true, KeyOpenedCallBack);
	}



}

 */


internal partial class SRP
{





}





