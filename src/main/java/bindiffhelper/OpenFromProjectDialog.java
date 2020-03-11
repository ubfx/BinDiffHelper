package bindiffhelper;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.util.Msg;

public class OpenFromProjectDialog extends DialogComponentProvider {
	
	private ProjectDataTreePanel tp;
	private BinDiffHelperPlugin plugin;
	
	public OpenFromProjectDialog(BinDiffHelperPlugin plugin)
	{
		super("Open File");
	
		this.plugin = plugin;
		
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
	
		
		tp = new ProjectDataTreePanel(null);
		tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());
		
		tp.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(tp, BorderLayout.CENTER);
		
		addWorkPanel(panel);

		okButton = new JButton("OK");
		okButton.addActionListener(e -> okCallback());
		addButton(okButton);

		cancelButton = new JButton("Cancel");
		cancelButton.setName("Cancel");
		cancelButton.addActionListener(e -> cancelCallback());
		addButton(cancelButton);
	}
	
	@Override
	protected void okCallback() {		
		if (tp.getSelectedItemCount() != 1)
		{
			Msg.showError(this, getComponent(), "Error", "Please select one file");
			return;
		}
		
		if (tp.getSelectedDomainFolder() != null)
		{
			Msg.showError(this, getComponent(), "Error", 
					"You seem to have selected a folder. Please select a single file.");
			return;
		}
		
		var df = tp.getSelectedDomainFile();
		if (df == null)
		{
			Msg.showError(this, getComponent(), "Error", 
					"No valid selection");
			return;
		}
		
		close();
		
		var files = plugin.callBinDiff(df);
		
		plugin.provider.openBinDiffDB(files[2].getAbsolutePath(), files[0], files[1]);
	}
}
