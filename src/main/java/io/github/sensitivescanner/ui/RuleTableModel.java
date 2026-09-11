package io.github.sensitivescanner.ui;

import io.github.sensitivescanner.model.ScanArea;
import io.github.sensitivescanner.rules.DetectionRule;
import io.github.sensitivescanner.scanner.ScanSettings;
import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.stream.Collectors;

final class RuleTableModel extends AbstractTableModel {
    private static final String[] COLUMNS={"Active","Description","Category","Regex","Sections","Source"};
    private final List<Entry> entries=new ArrayList<>();

    RuleTableModel(List<DetectionRule> rules){for(DetectionRule rule:rules)entries.add(new Entry(rule,true,rule.areas()));}
    public int getRowCount(){return entries.size();}
    public int getColumnCount(){return COLUMNS.length;}
    public String getColumnName(int c){return COLUMNS[c];}
    public Class<?> getColumnClass(int c){return c==0?Boolean.class:String.class;}
    public boolean isCellEditable(int r,int c){return c==0;}
    public Object getValueAt(int r,int c){Entry e=entries.get(r);return switch(c){case 0->e.enabled;case 1->e.rule.name();case 2->e.rule.category();case 3->e.rule.regex();case 4->format(e.areas);case 5->e.rule.custom()?"Custom":"Built-in";default->"";};}
    public void setValueAt(Object v,int r,int c){if(c==0){entries.get(r).enabled=Boolean.TRUE.equals(v);fireTableCellUpdated(r,c);}}

    DetectionRule ruleAt(int row){return entries.get(row).rule;}
    Set<ScanArea> areasAt(int row){return Set.copyOf(entries.get(row).areas);}
    List<DetectionRule> rules(){return entries.stream().map(e->e.rule).toList();}
    void setAll(boolean enabled){for(Entry e:entries)e.enabled=enabled;if(!entries.isEmpty())fireTableRowsUpdated(0,entries.size()-1);}
    void add(DetectionRule rule){int row=entries.size();entries.add(new Entry(rule,true,rule.areas()));fireTableRowsInserted(row,row);}
    void replace(int row,DetectionRule rule,Set<ScanArea> areas){Entry old=entries.get(row);entries.set(row,new Entry(rule,old.enabled,areas));fireTableRowsUpdated(row,row);}
    void setAreas(int row,Set<ScanArea> areas){entries.get(row).areas=Set.copyOf(areas);fireTableRowsUpdated(row,row);}
    void remove(int row){entries.remove(row);fireTableRowsDeleted(row,row);}
    void apply(ScanSettings settings){for(Entry e:entries){if(!e.enabled)settings.disabledRules.add(e.rule.id());settings.ruleAreas.put(e.rule.id(),Set.copyOf(e.areas));}}

    private String format(Set<ScanArea> areas){return areas.stream().sorted().map(ScanArea::label).collect(Collectors.joining(", "));}
    private static final class Entry {private final DetectionRule rule;private boolean enabled;private Set<ScanArea> areas;private Entry(DetectionRule rule,boolean enabled,Set<ScanArea> areas){this.rule=rule;this.enabled=enabled;this.areas=Set.copyOf(areas);}}
}
