/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bindiffhelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "This plugin helps importing function names using BinDiff 6/7/8",
	description = "This plugin helps importing function names using BinDiff 6/7/8",
	servicesRequired = { CodeViewerService.class }
)
//@formatter:on
public class BinDiffHelperPlugin extends ProgramPlugin {

	BinDiffHelperProvider provider;
	Exporter binExportExporter;
	String binDiffBinary;
	String diffCommand;
	boolean enableNamespace;
	protected String defaultBinPath;
	protected String defaultDiffCommand;
	Program program;
	
	public final static String BDBINPROPERTY = "de.ubfx.bindiffhelper.bindiffbinary";
	public final static String DIFFCOMMAND = "de.ubfx.bindiffhelper.diffCommand";
	public final static String ENABLENAMESPACE = "de.ubfx.bindiffhelper.enableNamespace";
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinDiffHelperPlugin(PluginTool tool) {
		super(tool);

		binExportExporter = null;
		
		try {
			Class<?> binExportExporterClass = Class.forName("com.google.security.binexport.BinExportExporter");
			
			List<Exporter> list = new ArrayList<>(ClassSearcher.getInstances(Exporter.class));
			
			for (Exporter e: list)
			{
				if (e.getClass() == binExportExporterClass)
				{
					binExportExporter = e;
					break;
				}
			}
			
		} catch (ClassNotFoundException e) {
		}
		
		try {
			updateBinDiffBinary();
		} catch (Exception e) {
			
		}

		if (System.getProperty("os.name").toLowerCase().contains("win")) {
			defaultBinPath = "C:\\Program Files\\BinDiff\\bin\\bindiff.exe";
			defaultDiffCommand = "notepad++ -multiInst -nosession -lc -pluginMessage=compare \"$file1\" \"$file2\"";
		}
		if (System.getProperty("os.name").toLowerCase().contains("nix")) {
			// defaultBinPath = "/opt/bindiff/bin/bindiff";
			defaultDiffCommand = "x-terminal-emulator -e 'diff -u \"$file1\" \"$file2\"'";
		}

		binDiffBinary = Preferences.getProperty(BDBINPROPERTY, defaultBinPath);
		diffCommand = Preferences.getProperty(DIFFCOMMAND, defaultDiffCommand);
		enableNamespace = Boolean.parseBoolean(Preferences.getProperty(ENABLENAMESPACE, "false"));
		
		provider = new BinDiffHelperProvider(this, this.getCurrentProgram());
		provider.setTitle("BinDiffHelper");
		
		provider.addToTool();
	}
	
	File binExportDomainFile(DomainFile df)
	{
		File out = null;
		
		try {
			var dof = df.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
			
			if (dof instanceof Program)
			{
				out = File.createTempFile(df.getName() + "_bdh", ".BinExport");

				if (enableNamespace) {
					binExportExporter.setOptions(
							List.of(
									new Option("Prepend Namespace to Function Names", true)
							)
					);
				}
				
				if (binExportExporter.export(out, dof, null, TaskMonitor.DUMMY) == false)
				{
					out.delete();
					out = null;
				}
			}
			
			
			dof.release(this);
			
			
		} catch (Exception e) {
			out = null;
		}
		
		return out;
	}
	
	public void callBinDiff(DomainFile df, Consumer<File[]> callback)
	{
		if (binDiffBinary == null) {
			
			Msg.showError(this, null, "Error", "Unexpected error, no binDiffBinary found");
			callback.accept(null);
			return;
		}
		TaskDialog d = new TaskDialog("Exporting", true, false, true);
		d.setMaximum(5);

		new Thread(() -> {
			File[] ret = null;
			
			d.setMessage("Exporting primary file");
			final var sec = binExportDomainFile(df);
			d.incrementProgress(1);
			
			d.setMessage("Exporting secondary file");
			final var pri = binExportDomainFile(program.getDomainFile());
			d.incrementProgress(1);
			
			d.setMessage("Executing BinDiff");
			
			String outputDir = pri.getParentFile().getAbsolutePath();
			
			String[] cmd = {binDiffBinary, pri.getAbsolutePath(), sec.getAbsolutePath(), "--output_dir", outputDir};
			
			Msg.debug(this, "bd: " + binDiffBinary + "\nfiles:" + pri.getAbsolutePath() + "," + sec.getAbsolutePath() + "\n"+
					"output dir: " + outputDir);
			Msg.debug(this, "printing BD output for cmd: " + Arrays.toString(cmd));
			Process p = null;
			try {
				ProcessBuilder pb = new ProcessBuilder(cmd);
				pb.redirectErrorStream(true);
				p = pb.start();

				Process finalP = p;
				Thread outputReader = new Thread(() -> {
					try (BufferedReader reader = new BufferedReader(new InputStreamReader(finalP.getInputStream()))) {
						String line;
						while ((line = reader.readLine()) != null) {
							Msg.debug(this, "> " + line);
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				});
				outputReader.start();

				while (!p.waitFor(1, TimeUnit.SECONDS)) {
					d.checkCanceled();
				}

				outputReader.join();
				int exitCode = p.exitValue();
				Msg.debug(this, "Process exited with code: " + exitCode);
				Msg.debug(this, "end of output");
				
			} catch (IOException | InterruptedException e) {
				Msg.showError(this, d.getComponent(), "Error", "Error when Exporting");
				d.close();
				callback.accept(null);
				return;
			} catch (CancelledException e) {
				if (p != null) {
					p.destroyForcibly();
				}
				d.close();
				
				callback.accept(null);
				return;
			}
			
			d.incrementProgress(1);
			d.setMessage("Looking for generated file");
			
			Path bindiff = FileSystems.getDefault().getPath(outputDir,
					pri.getName().replace(".BinExport", "") + 
					"_vs_" +
					sec.getName().replace(".BinExport", "")
					+ ".BinDiff");
			
			Msg.debug(this, "looking for bindiff at " + bindiff.toFile().getAbsolutePath());
			
			if (!bindiff.toFile().exists()) {
				ret = null;
				
				Msg.showError(this, d.getComponent(), "Error", "Error when trying to find generated BinDiff file");
			}
			else
			{
				ret = new File[] {pri, sec, bindiff.toFile()};
			}
			
			d.incrementProgress(1);
			d.close();
			
			
			callback.accept(ret);	
		}).start();
		tool.showDialog(d);
	}
	
	public boolean updateBinDiffBinary() throws IOException
	{
		String bin = Preferences.getProperty(BDBINPROPERTY);
		binDiffBinary = null;
		
		if (bin == null || bin.isEmpty()) {
			return false;
		}
		
		File f = new File(bin);
		if (!f.exists() || !f.canExecute())
		{
			throw new IOException("BinDiffBinary: File does not exist or is not executable");
		}
		
		String[] cmd = {bin, ""};
		try {
			var p = Runtime.getRuntime().exec(cmd);
			String outp = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
			
			p.waitFor();
			
			
			if (!outp.startsWith("BinDiff 6") && !outp.startsWith("BinDiff 7") && !outp.startsWith("BinDiff 8"))
			{
				throw new IOException("BinDiffBinary: This does not seem to be a BinDiff 6/7/8 binary");
			}
			
			
		} catch (Exception e) {
			throw new IOException("BinDiffBinary: Error running the file: " + e);			
		}
		
		binDiffBinary = bin;
		
		return true;		
	}
	
	public void updateDiffCommand(String cmd)
	{
		diffCommand = cmd == null || cmd.isEmpty() ? defaultDiffCommand : cmd;
		Preferences.setProperty(DIFFCOMMAND, cmd);
	}

	public void updateEnableNamespace(boolean enable)
	{
		enableNamespace = enable;
		Preferences.setProperty(ENABLENAMESPACE, Boolean.toString(enable));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	@Override
	protected void programActivated(Program p)
	{
		program = p;
		provider.setProgram(p);
	}
	
}
