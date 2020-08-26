package bindiffhelper;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.util.HTMLUtilities;
import resources.ResourceManager;

public class UpdatePlateCommentsAction extends DockingAction {
	protected BinDiffHelperPlugin plugin;
	List<ComparisonTableModel.Entry> entries;
	
	public UpdatePlateCommentsAction(BinDiffHelperPlugin plugin) {
		super("Create plate comments", plugin.getName());
		this.setMenuBarData(new MenuData(new String[] {"update", "Plate Comments"}));
		setToolBarData(new ToolBarData(ResourceManager.loadImage("images/Comment.png"), "Update Plate Comments"));
		setDescription(HTMLUtilities.toHTML("Set plate comments with similarity and links to other binary"));
		this.plugin = plugin;
	}

	public void setEntries(List<ComparisonTableModel.Entry> e) {
		entries = e;
	}
		
	/**
	 * Take a string, split it apart and replace a string prefixed by the value in key with the value in rep
	 * <p>
	 * This is a utility function I use to update comments for updating plate-comments at the top of functions
	 * <p>
	 * This function automatically adds the key as the leader for rep
	 *
	 * @param str The string we are scanning for a line to replace
	 * @param key The leader for the line we want to replace
	 * @param rep The value we want in the string
	 * @return A string with the line matching key replaced.  If no line matched, then we return rep
	 */
	public String updateKey(String str, String key, String rep) {
		String actualRep = String.format("%s: %s", key, rep);
		if(str == null) return actualRep;
		var strArr = str.split("\r?\n");
		StringBuilder res = new StringBuilder();


		boolean replaced = false;
		boolean prependSep = false;

		for(String s : strArr) {
			if(prependSep) res.append("\n");
			if(s.startsWith(key)) {
				res.append(actualRep);
				replaced = true;
				prependSep = true;
			}else {
				res.append(s);
				prependSep = true;
			}
		}

		if(replaced == false) {
			if(prependSep) res.append("\n");
			res.append(actualRep);
		}
		return res.toString();
	}

	@Override
	public void actionPerformed(ActionContext arg0) {
		int trans = plugin.program.startTransaction("Create Plate Comments");
		var symtab = plugin.program.getSymbolTable();
		var funmgr = plugin.program.getFunctionManager();
		
		for(ComparisonTableModel.Entry e : entries) {
			if(e.primaryAddress == null) continue; // If we don't have a primary address, there is nothing to comment.
			if(symtab.hasSymbol(e.primaryAddress)) {
				var f = funmgr.getFunctionAt(e.primaryAddress);
				String origComment = f.getComment();
				String newBindiffComment =
						String.format("*** %.2f%% match with %.2f%% confidence using %s ***"
								, e.similarity
								, e.confidence
								, e.algorithm );
				String newFunctionLinkComment = 
						String.format("*** %s@%08x {@program %s@%08x} ***"
								, e.secondaryFunctionName
								, e.secondaryAddress
								, plugin.provider.otherProg
								, e.secondaryAddress);
				String newComment = updateKey(origComment, "BINDIFF_COMMENT", newBindiffComment);
				newComment = updateKey(newComment, "BINDIFF_MATCHED_FN", newFunctionLinkComment);
				f.setComment(newComment);
			}
		}
		plugin.program.endTransaction(trans, true);
	}
}
