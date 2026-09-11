package io.github.sensitivescanner.ui;

import io.github.sensitivescanner.model.Finding;
import javax.swing.table.AbstractTableModel;
import java.util.*;

final class FindingTableModel extends AbstractTableModel {
    private final String[] columns={"Severity","Confidence","Description","Match","URL","Section"};
    private List<Finding> findings=List.of();
    void setFindings(List<Finding> values){findings=List.copyOf(values);fireTableDataChanged();}
    List<Finding> findings(){return findings;} Finding finding(int row){return findings.get(row);}
    public int getRowCount(){return findings.size();}public int getColumnCount(){return columns.length;}public String getColumnName(int c){return columns[c];}
    public Object getValueAt(int r,int c){Finding f=findings.get(r);return switch(c){case 0->f.severity();case 1->f.confidence();case 2->f.type();case 3->f.evidence();case 4->f.traffic().url();case 5->section(f);default->"";};}
    private String section(Finding f){return switch(f.location()){case REQUEST_URL,REQUEST_QUERY->"Request URL";case REQUEST_HEADER,REQUEST_COOKIE->"Request Headers";case REQUEST_BODY->"Request Body";case RESPONSE_HEADER,RESPONSE_COOKIE->"Response Headers";case RESPONSE_BODY,RESPONSE_JAVASCRIPT->"Response Body";};}
}
