package bindiffhelper;

import java.awt.BorderLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class OpenFromProjectDialog extends DialogComponentProvider {
	
	ProjectDataTreePanel tp;
	
	public OpenFromProjectDialog()
	{
		super("Open File");
		
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
		
		
		try {			
			var dof = df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
			
			if (dof instanceof ProgramDB)
			{
				System.out.println("ProgramDB");
			}
			
		} catch (VersionException | CancelledException | IOException e) {
			
			e.printStackTrace();
		}
		
	}
}
