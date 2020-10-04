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
	
	private JRadioButton rb0;
	private JRadioButton rb1;
	
	private String buildTable(String fn, String fnColor, String efn, String efnColor, String hash, String hashColor)
	{
		return "<html><table>"
				+ "<tr><td>Filename</td><td style='color: " + fnColor + ";'>" + fn + "</td></tr>"
				+ "<tr><td>Binary Filename</td><td style='color: " + efnColor + ";'>" + efn + "</td></tr>"
				+ "<tr><td>SHA256</td><td style='color: " + hashColor + ";'>" + hash + "</td></tr>"
				+ "</table></html>";
	}
	
	public MatchDialog(Program program, BinDiffFileDescriptor[] fds)
	{
		super("Match the loaded file to the correct BinDiff file");
	
		JLabel instructions = new JLabel("<html><p style='width:300px;text-align:center;'>"
				+ "The external BinDiff database has been loaded. "
				+ "Below, you need to select which of the files in the database matches the file loaded in Ghidra.<br/>"
				+ "The <b>other</b> file will be used to import function names from.</p><br/><br/></html>");
		
		JPanel work = new JPanel(new BorderLayout());
		work.add(instructions, BorderLayout.PAGE_START);
		
		JPanel panel = new JPanel(new BorderLayout());;
		
		JPanel ref = new JPanel();
		JPanel bd1 = new JPanel(new BorderLayout());
		JPanel bd2 = new JPanel(new BorderLayout());
		
		rb0 = new JRadioButton("This file matches the loaded file");
		rb1 = new JRadioButton("This file matches the loaded file");
		
		ButtonGroup bg = new ButtonGroup();
		bg.add(rb0);
		bg.add(rb1);
		
		bd1.add(rb0, BorderLayout.PAGE_START);
		bd2.add(rb1, BorderLayout.PAGE_START);
		
		ref.setBorder(BorderFactory.createTitledBorder("File loaded in Ghidra"));
		bd1.setBorder(BorderFactory.createTitledBorder("First file in BinDiff database"));
		bd2.setBorder(BorderFactory.createTitledBorder("Second file in BinDiff database"));
		
		panel.add(ref, BorderLayout.PAGE_START);
		panel.add(bd1, BorderLayout.LINE_START);
		panel.add(bd2, BorderLayout.LINE_END);
		
		
		String hashRef = program.getExecutableSHA256();
		String fnRef = program.getDomainFile().getName().toString();
		String efnRef = program.getName();
		
		String fnCol = fnRef.equalsIgnoreCase(fds[0].getFilename()) ? "green" : "red";
		String efnCol = efnRef.equalsIgnoreCase(fds[0].getExeFilename()) ? "green" : "red";
		String hashCol = hashRef.equalsIgnoreCase(fds[0].getHash()) ? "green" : "red";

		
		ref.add(new JLabel(buildTable(fnRef, "black", efnRef, "black", hashRef, "black")));
		bd1.add(new JLabel(buildTable(fds[0].getFilename(), fnCol, fds[0].getExeFilename(), efnCol, fds[0].getHash(), hashCol)));
		
		fnCol = fnRef.equalsIgnoreCase(fds[1].getFilename()) ? "green" : "red";
		efnCol = efnRef.equalsIgnoreCase(fds[1].getExeFilename()) ? "green" : "red";
		hashCol = hashRef.equalsIgnoreCase(fds[1].getHash()) ? "green" : "red";
		
		bd2.add(new JLabel(buildTable(fds[1].getFilename(), fnCol, fds[1].getExeFilename(), efnCol, fds[1].getHash(), hashCol)));
		
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
		close();
	}
	
	public int getSelected() {
		if (rb0.isSelected()) {
			return 0;
		}
		else if (rb1.isSelected()) {
			return 1;
		}
		return -1;
	}
}
