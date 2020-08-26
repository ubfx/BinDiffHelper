package bindiffhelper;

import java.awt.Color;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resources.ResourceManager;

public class UpdateFunctionColoringAction extends DockingAction {
	BinDiffHelperPlugin plugin;
	List<ComparisonTableModel.Entry> entries;

	public void setEntries(List<ComparisonTableModel.Entry> e) {
		entries = e;
	}
		
	public UpdateFunctionColoringAction(BinDiffHelperPlugin plugin) {
		super("Colorize functions based on similarity", plugin.getName());
		this.setMenuBarData(new MenuData(new String[] {"update", "Function Colors"}));
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/Comment.png"), "Colorize Similar Functions"));
		setDescription(HTMLUtilities.toHTML("Colorize functions that are similar according to bindiff"));
		this.plugin = plugin;
	}
	@Override
	public void actionPerformed(ActionContext arg0) {
		// TODO Auto-generated method stub
		int trans = plugin.program.startTransaction("Colorize Functions");
		var funmgr = plugin.program.getFunctionManager();
		ColorizingService crayon = plugin.getTool().getService(ColorizingService.class);
		if(crayon == null) {
			Msg.showError(this,  plugin.provider.getComponent(), "Failed to get colorizing service", "Failed to get colorizing service");
			plugin.program.endTransaction(trans, false);
			return;
		}
		for(ComparisonTableModel.Entry e : entries) {
			if(e.primaryAddress == null) continue; // If we don't have a primary address, there is nothing to comment.
			var f = funmgr.getFunctionAt(e.primaryAddress);
			if(f == null) continue; // If there isn't a function at the address, nothing to do
			var body = f.getBody();
			if(e.similarity > 0.90) {
				crayon.setBackgroundColor(body, Color.green);
			}
			if(e.similarity < 0.70) {
				crayon.setBackgroundColor(body, Color.RED);
			}
		}
		plugin.program.endTransaction(trans, true);

	}

}
