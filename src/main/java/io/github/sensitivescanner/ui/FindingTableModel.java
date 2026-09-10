package io.github.sensitivescanner.ui;

import io.github.sensitivescanner.model.Finding;
import javax.swing.table.AbstractTableModel;
import java.net.URI;
import java.util.*;

final class FindingTableModel extends AbstractTableModel {
    private final String[] columns={"Severity","Confidence","Type","Tool","Host","Method","Path","Location","Source","Evidence","Count"};
    private List<Finding> findings=List.of();
    void setFindings(List<Finding> values){findings=List.copyOf(values);fireTableDataChanged();}
    List<Finding> findings(){return findings;} Finding finding(int row){return findings.get(row);}
    public int getRowCount(){return findings.size();}public int getColumnCount(){return columns.length;}public String getColumnName(int c){return columns[c];}
    public Object getValueAt(int r,int c){Finding f=findings.get(r);return switch(c){case 0->f.severity();case 1->f.confidence();case 2->f.type();case 3->f.traffic().tool();case 4->f.traffic().host();case 5->f.traffic().method();case 6->path(f.traffic().url());case 7->f.location();case 8->f.traffic().source();case 9->f.maskedEvidence();case 10->f.occurrences();default->"";};}
    private String path(String u){try{URI uri=URI.create(u);String p=uri.getRawPath();return (p==null||p.isEmpty()?"/":p)+(uri.getRawQuery()==null?"":"?"+uri.getRawQuery());}catch(Exception e){return u;}}
}
