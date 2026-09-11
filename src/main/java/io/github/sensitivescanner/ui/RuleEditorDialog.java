package io.github.sensitivescanner.ui;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.rules.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;

final class RuleEditorDialog {
    record Result(DetectionRule rule,Set<ScanArea> areas){}

    static Result show(Component parent,DetectionRule existing,Set<ScanArea> selectedAreas){
        boolean custom=existing==null||existing.custom();
        JTextField name=new JTextField(existing==null?"":existing.name(),32);
        JTextField regex=new JTextField(existing==null?"":existing.regex(),48);
        JTextField description=new JTextField(existing==null?"":existing.description(),48);
        JComboBox<Severity> severity=new JComboBox<>(Severity.values());
        severity.setSelectedItem(existing==null?Severity.MEDIUM:existing.severity());
        name.setEnabled(custom);regex.setEnabled(custom);description.setEnabled(custom);severity.setEnabled(custom);

        JPanel areas=new JPanel(new FlowLayout(FlowLayout.LEFT,8,0));
        Map<ScanArea,JCheckBox> checks=new EnumMap<>(ScanArea.class);
        Set<ScanArea> initial=selectedAreas==null||selectedAreas.isEmpty()?Set.of(ScanArea.values()):selectedAreas;
        for(ScanArea area:ScanArea.values()){JCheckBox box=new JCheckBox(area.label(),initial.contains(area));checks.put(area,box);areas.add(box);}
        JPanel panel=new JPanel(new GridBagLayout());GridBagConstraints g=new GridBagConstraints();g.insets=new Insets(4,4,4,4);g.anchor=GridBagConstraints.WEST;g.fill=GridBagConstraints.HORIZONTAL;g.weightx=1;
        add(panel,g,0,"Name",name);add(panel,g,1,"Regex",regex);add(panel,g,2,"Description",description);add(panel,g,3,"Severity",severity);add(panel,g,4,"Scan sections",areas);
        if(!custom){g.gridx=0;g.gridy=5;g.gridwidth=2;panel.add(new JLabel("Built-in expressions are read-only; scan sections can be changed."),g);}

        while(true){
            int choice=JOptionPane.showConfirmDialog(parent,panel,existing==null?"Add custom regex":"Edit rule",JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE);
            if(choice!=JOptionPane.OK_OPTION)return null;
            EnumSet<ScanArea> chosen=EnumSet.noneOf(ScanArea.class);checks.forEach((a,b)->{if(b.isSelected())chosen.add(a);});
            if(chosen.isEmpty()){JOptionPane.showMessageDialog(parent,"Select at least one scan section.","Invalid rule",JOptionPane.ERROR_MESSAGE);continue;}
            if(!custom)return new Result(existing,chosen);
            try{
                String id=existing==null?"CUSTOM-"+UUID.randomUUID():existing.id();
                DetectionRule rule=new CustomRegexRule(id,name.getText(),regex.getText(),description.getText(),(Severity)severity.getSelectedItem(),chosen);
                return new Result(rule,chosen);
            }catch(IllegalArgumentException error){JOptionPane.showMessageDialog(parent,error.getMessage(),"Invalid rule",JOptionPane.ERROR_MESSAGE);}
        }
    }

    private static void add(JPanel panel,GridBagConstraints g,int row,String label,JComponent field){g.gridy=row;g.gridx=0;g.gridwidth=1;g.weightx=0;panel.add(new JLabel(label),g);g.gridx=1;g.weightx=1;panel.add(field,g);}
}
