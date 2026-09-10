package io.github.sensitivescanner.ui;

import io.github.sensitivescanner.rules.DetectionRule;
import javax.swing.table.AbstractTableModel;
import java.util.*;

final class RuleTableModel extends AbstractTableModel {
    private final List<DetectionRule> rules; private final boolean[] enabled;
    RuleTableModel(List<DetectionRule> rules){this.rules=rules;enabled=new boolean[rules.size()];Arrays.fill(enabled,true);}
    public int getRowCount(){return rules.size();}public int getColumnCount(){return 4;}public String getColumnName(int c){return new String[]{"Enabled","Rule ID","Name","Severity"}[c];}
    public Class<?> getColumnClass(int c){return c==0?Boolean.class:String.class;}public boolean isCellEditable(int r,int c){return c==0;}
    public Object getValueAt(int r,int c){DetectionRule rule=rules.get(r);return switch(c){case 0->enabled[r];case 1->rule.id();case 2->rule.name();default->rule.severity().name();};}
    public void setValueAt(Object v,int r,int c){if(c==0){enabled[r]=Boolean.TRUE.equals(v);fireTableCellUpdated(r,c);}}
    Set<String> disabled(){Set<String>s=new HashSet<>();for(int i=0;i<rules.size();i++)if(!enabled[i])s.add(rules.get(i).id());return s;}
}
