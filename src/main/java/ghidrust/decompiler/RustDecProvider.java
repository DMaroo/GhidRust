package ghidrust.decompiler;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidrust.decompiler.parser.c.CFormatter;
import ghidrust.decompiler.parser.c.gen.CParser;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.JButton;
import javax.swing.Box;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

import java.awt.BorderLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import docking.ComponentProvider;
import ghidra.util.task.ConsoleTaskMonitor;
import resources.ResourceManager;

/**
 * Responsible for decompiling and showing the decompiled code in a window.
 */
public class RustDecProvider extends ComponentProvider {
    private JPanel panel;
    private JTextArea codeArea;
    private JLabel funcTitle;

    private Program prog;
    private Address addr;

    private DecompInterface decompInterface = null;

    private static final String EMPTY_LABEL = "<none>";

    /**
     * Initialize the provider by creating a decompilation interface and the
     * decompilation window.
     *
     * @param plugin Calling plugin, which in our case would be RustDecPlugin.
     * @param owner Owner of the plugin.
     * @param p Program on which this plugin is being used.
     */
    public RustDecProvider(RustDecPlugin plugin, String owner, Program p) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/icon.png"));

        decompInterface = new DecompInterface();
        setProgram(p);

        buildPanel();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        funcTitle = new JLabel(EMPTY_LABEL);
        JButton reload = new JButton(ResourceManager.loadImage("images/reload.png"));

        reload.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                reload();
            }
        });

        JToolBar toolbar = new JToolBar("GhidRust", JToolBar.HORIZONTAL);
        toolbar.setFloatable(false);
        toolbar.add(funcTitle);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(reload);

        codeArea = new JTextArea();
        codeArea.setEditable(false);

        JScrollPane scroll = new JScrollPane(codeArea);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        panel.add(toolbar, BorderLayout.PAGE_START);
        panel.add(scroll);
    }

    public void activateProvider() {
        setVisible(true);
    }

    /**
     * We save the program in a private class variable to be used later, and
     * open it using the decompiler interface.
     *
     * @param p program to be decompiled.
     */
    public void setProgram(Program p) {
        prog = p;

        decompInterface.closeProgram();
        if (prog != null) {
            decompInterface.openProgram(prog);
        }
    }

    public void setLocation(Address a) {
        addr = a;
    }

    /**
     * When reload is called, we trigger the decompilation.
     */
    public void reload() {
        if (prog == null) {
            funcTitle.setText(EMPTY_LABEL);
            codeArea.setText("[?] Open a program to see the decompilation!\n");
            return;
        }

        if (addr == null) {
            funcTitle.setText(EMPTY_LABEL);
            codeArea.setText("[?] Select a memory location to decompile!\n");
            return;
        }

        Function func = prog.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            funcTitle.setText(EMPTY_LABEL);
            codeArea.setText("[!] No function found at " + addr.toString() + "\n");
            return;
        }

        funcTitle.setText(func.getName());

        if (decompInterface == null) {
            codeArea.setText("[!] Decompiler has not been initialized!\n");
            return;
        }

        DecompileResults results = decompInterface.decompileFunction(
            func, 0, new ConsoleTaskMonitor()
        );
        if (results == null || results.getDecompiledFunction() == null
            || results.getDecompiledFunction().getC() == null) {
            codeArea.setText("[!] Failed to decompile " + func.getName() + "\n");
            return;
        }

        String decompiled = results.getDecompiledFunction().getC();
        String rustCode = "";

        try {
            rustCode = CFormatter.format(CParser.transpile(decompiled));
        } catch (Exception e) {
            rustCode = "/* [!] Failed to transpile " + func.getName() + " */\n" + decompiled;
        }

        codeArea.setText(rustCode);
    }
}
