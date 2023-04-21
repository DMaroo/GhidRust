package ghidrust.decompiler;

import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

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

public class RustDecProvider extends ComponentProvider {
    private JPanel panel;
    private JTextArea code_area;
    private JLabel func_title;

    private Program prog;
    private Address addr;

    private DecompInterface decomp_ifc = null;

    private static final String EMPTY_LABEL = "<none>";

    public RustDecProvider(RustDecPlugin plugin, String owner, Program p) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/icon.png"));

        decomp_ifc = new DecompInterface();
        setProgram(p);

        buildPanel();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        func_title = new JLabel(EMPTY_LABEL);
        JButton reload = new JButton(ResourceManager.loadImage("images/reload.png"));

        reload.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                reload();
            }
        });

        JToolBar toolbar = new JToolBar("GhidRust", JToolBar.HORIZONTAL);
        toolbar.setFloatable(false);
        toolbar.add(func_title);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(reload);

        code_area = new JTextArea();
        code_area.setEditable(false);

        JScrollPane scroll = new JScrollPane(code_area);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        panel.add(toolbar, BorderLayout.PAGE_START);
        panel.add(scroll);
    }

    public void activateProvider() {
        setVisible(true);
    }

    public void setProgram(Program p) {
        prog = p;

        decomp_ifc.closeProgram();
        if (prog != null) {
            decomp_ifc.openProgram(prog);
        }
    }

    public void setLocation(Address a) {
        addr = a;
    }

    public void reload() {
        if (prog == null) {
            func_title.setText(EMPTY_LABEL);
            code_area.setText("[?] Open a program to see the decompilation!\n");
            return;
        }

        if (addr == null) {
            func_title.setText(EMPTY_LABEL);
            code_area.setText("[?] Select a memory location to decompile!\n");
            return;
        }

        Function func = prog.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            func_title.setText(EMPTY_LABEL);
            code_area.setText("[!] No function found at " + addr.toString() + "\n");
            return;
        }

        func_title.setText(func.getName());

        if (decomp_ifc == null) {
            code_area.setText("[!] Decompiler has not been initialized!\n");
            return;
        }

        DecompileResults results = decomp_ifc.decompileFunction(func, 0, new ConsoleTaskMonitor());
        if (results == null || results.getDecompiledFunction() == null) {
            code_area.setText("[!] Failed to decompile " + func.getName() + "\n");
            return;
        }

        code_area.setText(results.getDecompiledFunction().getC());
    }
}
