package bindiffhelper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import resources.ResourceManager;

public class ImportFunctionNamesAction extends DockingAction {

	protected FlatProgramAPI api;
	protected BinDiffHelperPlugin plugin;
	
	List<ComparisonTableModel.Entry> entries;
	
	public ImportFunctionNamesAction(BinDiffHelperPlugin plugin)
	{
		super("Import selected function names", plugin.getName());
		
		this.setMenuBarData(new MenuData(new String[] { "Import", "Selected function names" }, "Import"));
		
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_go.png"), ""));

		setDescription(HTMLUtilities.toHTML("Import selected function names"));
		
		this.plugin = plugin;
	}

	public void setEntries(List<ComparisonTableModel.Entry> e) {
		entries = e;
	}
	
	@Override
	public void actionPerformed(ActionContext arg0) {
		
		var map = new HashMap<Symbol, String>();
		
		for (var e : entries) {
			if (!e.do_import)
				continue;
			
			map.put(e.primaryFunctionSymbol, e.secondaryFunctionName);
		}

		plugin.provider.execute(new RenameCmd(map));
		plugin.provider.refresh();
	}
	
	final class RenameCmd implements Command
	{
		Map<Symbol, String> map;
		
		public RenameCmd(Map<Symbol, String> m)
		{
			map = m;
		}
		
		@Override
		public boolean applyTo(DomainObject arg0) {
			try {
				
				for (var e: map.entrySet())
				{
					e.getKey().setName(e.getValue(), SourceType.IMPORTED);
				}
			} catch (DuplicateNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return true;
		}

		@Override
		public String getName() {
			return "Rename symbols";
		}

		@Override
		public String getStatusMsg() {
			return null;
		}
		
	}
}