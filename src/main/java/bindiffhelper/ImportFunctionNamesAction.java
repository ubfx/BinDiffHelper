package bindiffhelper;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.HTMLUtilities;
import resources.ResourceManager;

public class ImportFunctionNamesAction extends DockingAction {

	protected FlatProgramAPI api;
	
	public ImportFunctionNamesAction(BinDiffHelperPlugin plugin, FlatProgramAPI api)
	{
		super("Import selected function names", plugin.getName());
		
		this.api = api;
		
		this.setMenuBarData(new MenuData(new String[] { "Import", "Selected function names" }, "Import"));
		
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/BDH.png"), ""));

		setDescription(HTMLUtilities.toHTML("Import selected function names"));
	}

	@Override
	public void actionPerformed(ActionContext arg0) {
		// TODO Auto-generated method stub
		
	}
}