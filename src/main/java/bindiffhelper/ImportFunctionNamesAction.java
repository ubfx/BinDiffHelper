package bindiffhelper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resources.ResourceManager;

public class ImportFunctionNamesAction extends DockingAction {
	
	protected BinDiffHelperPlugin plugin;
	
	List<ComparisonTableModel.Entry> entries;
	
	public ImportFunctionNamesAction(BinDiffHelperPlugin plugin)
	{
		super("Import selected function names", plugin.getName());
		
		this.setMenuBarData(new MenuData(new String[] { "Import", "Selected function names" }, "Import"));
		
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_go.png"), "Import"));

		setDescription(HTMLUtilities.toHTML("Import selected function names"));
		
		this.plugin = plugin;
	}

	public void setEntries(List<ComparisonTableModel.Entry> e) {
		entries = e;
	}
	
	@Override
	public void actionPerformed(ActionContext arg0) {
		int trans = plugin.program.startTransaction("Rename functions");
		
		Map<String, Exception> changes = new HashMap<String, Exception>();
		
		for (var e : entries) {
			if (!e.do_import)
				continue;
			
			Exception exp = null;
			String transformation = e.primaryFunctionSymbol.getName() + " -> " + e.secondaryFunctionName;
			try {
				e.primaryFunctionSymbol.setName(e.secondaryFunctionName, SourceType.IMPORTED);
				e.do_import = false;
			} catch (Exception ex) {
				exp = ex;
			}
			
			changes.put(transformation, exp);
		}

		plugin.program.endTransaction(trans, true);

		String html = "<html><ul>";
		
		for (var c: changes.entrySet())
		{
			boolean wasSuccess = c.getValue() == null;
			
			String color = wasSuccess ? "green" : "red";
			
			html += "<li><font color='" + color + "'>" + c.getKey();
			
			if (!wasSuccess)
			{
				html += " unsuccessful (Exception: " + c.getValue().toString() + ")";
			}
			
			html += "</font></li>";
		}
		
		html += "</ul></html>";
		
		plugin.provider.refresh();
		Msg.showInfo(this, plugin.provider.getComponent(), "Renamed functions", html);
	}
	
}