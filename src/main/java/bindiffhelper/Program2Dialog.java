package bindiffhelper;

import java.awt.Component;
import java.awt.Dimension;
import java.util.Collections;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.Tool;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class Program2Dialog extends DialogComponentProvider {
	
	private ProjectDataTreePanel tp;
	private DomainFile df;
	private Program newProgram;
	private CodeViewerService cvs;

	private BinDiffHelperPlugin plugin;


	public Program2Dialog(BinDiffHelperPlugin plugin)
	{
		super("Select the second program");

		this.plugin = plugin;
			
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		
		JLabel l = new JLabel("<html><p style='width:300px;'>In this dialog, you can select the program that matches "
				+ "the file will be diffed to.</p><br/><br/></html>");
				
		panel.add(l);

		JPanel projectPanel;
		tp = new ProjectDataTreePanel(null);
		tp.setProjectData(AppInfo.getActiveProject().getName(), AppInfo.getActiveProject().getProjectData());
		tp.setPreferredSize(new Dimension(400, 300));
		projectPanel = tp;

		projectPanel.setBorder(BorderFactory.createTitledBorder("Select the second program"));
		projectPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.add(projectPanel);
		
		panel.add(Box.createRigidArea(new Dimension(0, 20)));

		addWorkPanel(panel);

		okButton = new JButton("OK");
		okButton.addActionListener(e -> okCallback());
		addButton(okButton);

		cancelButton = new JButton("Skip");
		cancelButton.setName("Skip");
		cancelButton.addActionListener(e -> cancelCallback());
		addButton(cancelButton);
	}

	public DomainFile getDomainFile()
	{
		return df;
	}

	public CodeViewerService getCodeViewerService()
	{
		return cvs;
	}

	public Program openProgram() {
		try {
			Tool newTool = plugin.getTool().getToolServices().launchDefaultTool(Collections.singletonList(df));
			DomainObject domainObject = df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
			newProgram = (Program) domainObject;
			cvs = newTool.getService(CodeViewerService.class);
        } catch (Exception e) {
            Msg.showError(this, getComponent(), "Error",
					"Failed to open the program in new window: " + e.getMessage());
        }
		return newProgram;
	}
	
	@Override
	protected void okCallback() {
		if (tp.getSelectedItemCount() == 1) {
			if (tp.getSelectedDomainFolder() != null) {
				Msg.showError(this, getComponent(), "Error", 
						"You seem to have selected a folder. Please select a single file.");
				return;
			}
			
			df = tp.getSelectedDomainFile();
			if (df == null)	{
				Msg.showError(this, getComponent(), "Error", "No valid selection");
				return;
			}			
		}
		else {
			Msg.showError(this, getComponent(), "Error", "No valid selection");
			return;
		}
		close();
	}
}
