package bindiffhelper;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import bindiffhelper.BinDiffHelperProvider.BinDiffFileDescriptor;
import docking.DialogComponentProvider;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class MatchDialog extends DialogComponentProvider {
	
	private int index;
	
	public MatchDialog(Program program, BinDiffFileDescriptor[] fds)
	{
		super("Match the loaded file to the correct BinDiff file");
	
		index = -1;
		JLabel instructions = new JLabel("<html><p style='width:300px;'>The external BinDiff database has been loaded.<br/>"
				+ "Below, you need to select which of the files in the database matches the file loaded in Ghidra.<br/>"
				+ "The <b>other</b> file will be used to import function names from.</p></html>");
		
		JPanel work = new JPanel(new BorderLayout());
		work.add(instructions, BorderLayout.PAGE_START);
		
		JPanel panel = new JPanel(new BorderLayout());;
		
		JPanel ref = new JPanel();
		JPanel bd1 = new JPanel(new BorderLayout());
		JPanel bd2 = new JPanel(new BorderLayout());
		
		JRadioButton rb1 = new JRadioButton("This file matches the loaded file");
		JRadioButton rb2 = new JRadioButton("This file matches the loaded file");
		
		ButtonGroup bg = new ButtonGroup();
		bg.add(rb1);
		bg.add(rb2);
		
		bd1.add(rb1, BorderLayout.PAGE_START);
		bd2.add(rb2, BorderLayout.PAGE_START);
		
		ref.setBorder(BorderFactory.createTitledBorder("File loaded in Ghidra"));
		bd1.setBorder(BorderFactory.createTitledBorder("First file in BinDiff database"));
		bd2.setBorder(BorderFactory.createTitledBorder("Second file in BinDiff database"));
		
		panel.add(ref, BorderLayout.PAGE_START);
		panel.add(bd1, BorderLayout.LINE_START);
		panel.add(bd2, BorderLayout.LINE_END);
		
		ref.add(new JLabel("ref " + program.getExecutableSHA256()));
		bd1.add(new JLabel("bd1"));
		bd2.add(new JLabel("bd2"));
		
		work.add(panel, BorderLayout.PAGE_END);
		
		addWorkPanel(work);

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
		
	}
}
