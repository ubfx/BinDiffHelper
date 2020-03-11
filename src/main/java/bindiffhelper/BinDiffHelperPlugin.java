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
import java.util.List;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "This plugin helps importing function names using BinDiff 6",
	description = "This plugin helps importing function names using BinDiff 6",
	servicesRequired = { CodeViewerService.class }
)
//@formatter:on
public class BinDiffHelperPlugin extends ProgramPlugin {

	BinDiffHelperProvider provider;
	Exporter binExportExporter;
	String binDiff6Binary;
	
	Program program;
	
	public final static String BD6BINPROPERTY = "de.ubfx.bindiffhelper.bindiff6binary";
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinDiffHelperPlugin(PluginTool tool) {
		super(tool, true, true);

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
		
		provider = new BinDiffHelperProvider(this, this.getCurrentProgram());
		provider.setTitle("BinDiffHelper");
		
		try {
			updateBinDiff6Binary();
		} catch (Exception e) {
			
		}
		provider.settingsUpdated();
		
		provider.addToTool();
	}
	
	File binExportDomainFile(DomainFile df)
	{
		File out = null;
		
		try {			
			var dof = df.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
			
			if (dof instanceof Program)
			{
				out = File.createTempFile(df.getName(), ".BinExport");
				
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
	
	public File[] callBinDiff(DomainFile df)
	{
		if (binDiff6Binary == null) {
			
			Msg.showError(this, null, "Error", "Unexpected error, no binDiffBinary found");
			return null;
		}
		
		File[] ret = null;
		
		TaskDialog d = new TaskDialog("Exporting", false, false, true);
		tool.showDialog(d);
		d.setMaximum(5);
		d.setMessage("Exporting primary file");
		final var sec = binExportDomainFile(df);
		d.incrementProgress(1);
		
		d.setMessage("Exporting secondary file");
		final var pri = binExportDomainFile(program.getDomainFile());
		d.incrementProgress(1);
		
		d.setMessage("Executing BinDiff 6");
		
		String outputDir = pri.getParentFile().getAbsolutePath();
		
		String[] cmd = {binDiff6Binary, pri.getAbsolutePath(), sec.getAbsolutePath(), "--output_dir", outputDir};
		
		Msg.debug(this, "bd6: " + binDiff6Binary + "\nfiles:" + pri.getAbsolutePath() + "," + sec.getAbsolutePath() + "\n"+
				"output dir: " + outputDir);
		Msg.debug(this, "printing BD6 output");
		try {
			var p = Runtime.getRuntime().exec(cmd);
			p.waitFor();
			var i = new BufferedReader(new InputStreamReader(p.getInputStream()));
			while (true)
			{
				String line = i.readLine();
				
				if (line == null)
					break;
				
				Msg.debug(this, ">" + line);
			}
			Msg.debug(this, "end of output");
			
		} catch (IOException | InterruptedException e) {
			Msg.showError(this, d.getComponent(), "Error", "Error when Exporting");
			d.close();
			return null;
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
		
		
		return ret;
	}
	
	public boolean updateBinDiff6Binary() throws IOException
	{
		String bin = Preferences.getProperty(BD6BINPROPERTY);
		binDiff6Binary = null;
		
		if (bin == null || bin.isEmpty()) {
			return false;
		}
		
		File f = new File(bin);
		if (!f.exists() || !f.canExecute())
		{
			throw new IOException("File does not exist or is not executable");
		}
		
		String[] cmd = {bin, ""};
		try {
			var p = Runtime.getRuntime().exec(cmd);
			String outp = new BufferedReader(new InputStreamReader(p.getInputStream())).readLine();
			
			p.waitFor();
			
			
			if (!outp.startsWith("BinDiff 6"))
			{
				throw new IOException("This does not seem to be a BinDiff 6 binary");
			}
			
			
		} catch (Exception e) {
			throw new IOException("Couldn't run this file. Doesn't seem to be the correct BinDiff 6 binary");			
		}
		
		binDiff6Binary = bin;
		
		return true;		
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
