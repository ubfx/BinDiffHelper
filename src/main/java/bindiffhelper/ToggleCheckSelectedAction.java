package bindiffhelper;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.util.HTMLUtilities;
import resources.ResourceManager;

public class ToggleCheckSelectedAction extends DockingAction {

	protected BinDiffHelperPlugin plugin;

	public ToggleCheckSelectedAction(BinDiffHelperPlugin plugin) {
		super("Toggle selected functions", plugin.getName());

		this.setMenuBarData(new MenuData(new String[] { "Toggle selected functions" }));

		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/check_box.png"), "Import"));

		setDescription(HTMLUtilities.toHTML("Toggle the selected functions in the table"));

		this.plugin = plugin;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// TODO Auto-generated method stub
		if (plugin.provider.table != null) {
			for (var i : plugin.provider.table.getSelectedRows()) {
				Boolean currentlyChecked = (Boolean) plugin.provider.ctm.getValueAt(i, 0);

				plugin.provider.ctm.setValueAt(!currentlyChecked, i, 0);
			}
		}

	}

}
