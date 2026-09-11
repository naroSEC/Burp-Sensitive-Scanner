package io.github.sensitivescanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.*;
import io.github.sensitivescanner.burp.TrafficCollector;
import io.github.sensitivescanner.export.FindingExporter;
import io.github.sensitivescanner.importer.LoggerCsvImporter;
import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.rules.*;
import io.github.sensitivescanner.scanner.*;
import io.github.sensitivescanner.traffic.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SensitiveScannerPanel extends JPanel {
    private final MontoyaApi api;
    private final TrafficRepository capturedRepository,importedRepository;
    private final TrafficCollector collector;
    private final List<DetectionRule> rules=RuleCatalog.defaults();
    private final JCheckBox proxy=new JCheckBox("Proxy History",true),siteMap=new JCheckBox("Site Map",true),live=new JCheckBox("Captured Burp Traffic",true),logger=new JCheckBox("Imported Logger CSV",true);
    private final JComboBox<String> scope=new JComboBox<>(new String[]{"Burp Suite Target scope only","All traffic"});
    private final JCheckBox requestUrl=new JCheckBox("Request URL",true),requestHeaders=new JCheckBox("Request headers",true),requestBody=new JCheckBox("Request body",true),responseHeaders=new JCheckBox("Response headers",true),responseBody=new JCheckBox("Response body",true);
    private final JSpinner maxBody=new JSpinner(new SpinnerNumberModel(2,1,16,1)),decodeDepth=new JSpinner(new SpinnerNumberModel(2,0,5,1)),entropy=new JSpinner(new SpinnerNumberModel(3.5,0.0,8.0,0.1)),maxEntries=new JSpinner(new SpinnerNumberModel(20000,100,500000,100));
    private final JComboBox<Confidence> minConfidence=new JComboBox<>(Confidence.values());
    private final JLabel importStatus=new JLabel("Imported Logger: none"),summary=new JLabel("Ready"),eviction=new JLabel(" ");
    private final JProgressBar progress=new JProgressBar();
    private final JButton scanButton=new JButton("Scan Existing Traffic"),stopButton=new JButton("Stop");
    private final FindingTableModel findingModel=new FindingTableModel();
    private final JTable findings=new JTable(findingModel);
    private final TableRowSorter<FindingTableModel> findingSorter=new TableRowSorter<>(findingModel);
    private final JTextField findingFilter=new JTextField(30);
    private final RuleTableModel ruleModel=new RuleTableModel(rules);
    private final JTable ruleTable=new JTable(ruleModel);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextArea details=new JTextArea();
    private volatile SwingWorker<DetectionEngine.ScanResult,Void> worker;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private volatile long lastProgressUpdate;

    public SensitiveScannerPanel(MontoyaApi api,TrafficRepository capturedRepository,TrafficRepository importedRepository,TrafficCollector collector){
        super(new BorderLayout(6,6));this.api=api;this.capturedRepository=capturedRepository;this.importedRepository=importedRepository;this.collector=collector;
        requestEditor=api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);responseEditor=api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        setBorder(new EmptyBorder(8,8,8,8));add(buildControls(),BorderLayout.NORTH);add(buildContent(),BorderLayout.CENTER);wire();stopButton.setEnabled(false);details.setEditable(false);details.setFont(new Font(Font.MONOSPACED,Font.PLAIN,12));
    }

    private JComponent buildControls(){
        JPanel root=new JPanel();root.setLayout(new BoxLayout(root,BoxLayout.Y_AXIS));
        JPanel sources=new JPanel(new FlowLayout(FlowLayout.LEFT));sources.setBorder(BorderFactory.createTitledBorder("Traffic Sources"));sources.add(proxy);sources.add(siteMap);sources.add(live);sources.add(logger);sources.add(scope);JButton importButton=new JButton("Import Logger CSV");sources.add(importButton);sources.add(importStatus);root.add(sources);importButton.addActionListener(e->chooseImport());
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));actions.add(scanButton);actions.add(stopButton);JButton clear=new JButton("Clear Results"),json=new JButton("Export JSON"),csv=new JButton("Export CSV");actions.add(clear);actions.add(json);actions.add(csv);progress.setStringPainted(true);progress.setPreferredSize(new Dimension(260,24));actions.add(progress);actions.add(summary);root.add(actions);clear.addActionListener(e->{findingModel.setFindings(List.of());summary.setText("Results cleared");});json.addActionListener(e->chooseExport(true));csv.addActionListener(e->chooseExport(false));
        JPanel settings=new JPanel(new FlowLayout(FlowLayout.LEFT));settings.setBorder(BorderFactory.createTitledBorder("Scan Areas and Limits"));settings.add(requestUrl);settings.add(requestHeaders);settings.add(requestBody);settings.add(responseHeaders);settings.add(responseBody);settings.add(new JLabel("Max body MiB"));settings.add(maxBody);settings.add(new JLabel("Entropy"));settings.add(entropy);settings.add(new JLabel("Decode depth"));settings.add(decodeDepth);settings.add(new JLabel("Minimum confidence"));settings.add(minConfidence);settings.add(new JLabel("Collector entries"));settings.add(maxEntries);settings.add(eviction);root.add(settings);
        return root;
    }

    private JComponent buildContent(){
        findings.setRowSorter(findingSorter);findings.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);findings.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);int[] widths={80,90,190,250,430,140};for(int i=0;i<findings.getColumnCount();i++)findings.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel filterBar=new JPanel(new FlowLayout(FlowLayout.LEFT));filterBar.add(new JLabel("Filter results"));filterBar.add(findingFilter);JPanel findingList=new JPanel(new BorderLayout());findingList.add(filterBar,BorderLayout.NORTH);findingList.add(new JScrollPane(findings),BorderLayout.CENTER);
        JTabbedPane messageTabs=new JTabbedPane();messageTabs.addTab("Request",requestEditor.uiComponent());messageTabs.addTab("Response",responseEditor.uiComponent());messageTabs.addTab("Finding Details",new JScrollPane(details));JSplitPane vertical=new JSplitPane(JSplitPane.VERTICAL_SPLIT,findingList,messageTabs);vertical.setResizeWeight(.55);
        JTabbedPane main=new JTabbedPane();main.addTab("Findings",vertical);main.addTab("Rules",buildRulesPanel());return main;
    }

    private JComponent buildRulesPanel(){
        ruleTable.setAutoCreateRowSorter(true);ruleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);ruleTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);int[] widths={55,210,130,420,360,80};for(int i=0;i<ruleTable.getColumnCount();i++)ruleTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel buttons=new JPanel(new FlowLayout(FlowLayout.LEFT));JButton add=new JButton("Add Regex"),edit=new JButton("Edit"),remove=new JButton("Delete"),enable=new JButton("Enable All"),disable=new JButton("Disable All");buttons.add(add);buttons.add(edit);buttons.add(remove);buttons.add(enable);buttons.add(disable);add.addActionListener(e->addRule());edit.addActionListener(e->editRule());remove.addActionListener(e->removeRule());enable.addActionListener(e->ruleModel.setAll(true));disable.addActionListener(e->ruleModel.setAll(false));
        JPanel panel=new JPanel(new BorderLayout());panel.add(buttons,BorderLayout.NORTH);panel.add(new JScrollPane(ruleTable),BorderLayout.CENTER);return panel;
    }

    private void wire(){
        scanButton.addActionListener(e->startScan());stopButton.addActionListener(e->{cancelled.set(true);summary.setText("Stopping…");});findings.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()&&findings.getSelectedRow()>=0)showFinding(findingModel.finding(findings.convertRowIndexToModel(findings.getSelectedRow())));});maxEntries.addChangeListener(e->{capturedRepository.setMaxEntries((Integer)maxEntries.getValue());updateEviction();});
        findingFilter.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){filterFindings();}public void removeUpdate(DocumentEvent e){filterFindings();}public void changedUpdate(DocumentEvent e){filterFindings();}});
    }

    private ScanSettings settings(){
        ScanSettings s=new ScanSettings();s.maximumBodySize=(Integer)maxBody.getValue()*1024*1024;s.maximumInputSize=s.maximumBodySize+1024*1024;s.maximumDecodedSize=s.maximumBodySize;s.maximumDecodeDepth=(Integer)decodeDepth.getValue();s.entropyThreshold=(Double)entropy.getValue();s.minimumConfidence=(Confidence)minConfidence.getSelectedItem();s.enabledAreas.clear();if(requestUrl.isSelected())s.enabledAreas.add(ScanArea.REQUEST_URL);if(requestHeaders.isSelected())s.enabledAreas.add(ScanArea.REQUEST_HEADERS);if(requestBody.isSelected())s.enabledAreas.add(ScanArea.REQUEST_BODY);if(responseHeaders.isSelected())s.enabledAreas.add(ScanArea.RESPONSE_HEADERS);if(responseBody.isSelected())s.enabledAreas.add(ScanArea.RESPONSE_BODY);s.scanRequest=requestUrl.isSelected()||requestHeaders.isSelected()||requestBody.isSelected();s.scanResponse=responseHeaders.isSelected()||responseBody.isSelected();ruleModel.apply(s);return s;
    }

    private void startScan(){
        if(worker!=null&&!worker.isDone())return;cancelled.set(false);lastProgressUpdate=0;scanButton.setEnabled(false);stopButton.setEnabled(true);progress.setValue(0);summary.setText("Scanning traffic…");ScanSettings settings=settings();DetectionEngine engine=new DetectionEngine(ruleModel.rules());boolean useProxy=proxy.isSelected(),useSiteMap=siteMap.isSelected(),useLive=live.isSelected(),useLogger=logger.isSelected(),inScopeOnly=scope.getSelectedIndex()==0;
        worker=new SwingWorker<>(){
            protected DetectionEngine.ScanResult doInBackground(){DetectionEngine.ScanSession session=engine.newSession(settings,cancelled);TrafficCollector.CollectionResult c=collector.stream(useProxy,useSiteMap,useLive,useLogger,inScopeOnly,settings.maximumInputSize,cancelled,session::accept,SensitiveScannerPanel.this::updateScanProgress);return session.finish(c.collected(),c.skippedOversized(),c.errors());}
            protected void done(){try{DetectionEngine.ScanResult r=get();findingModel.setFindings(r.findings());String retained=r.omittedRawMessages()>0?" | Raw omitted "+r.omittedRawMessages():"";String dropped=r.droppedFindings()>0?" | Findings capped "+r.droppedFindings():"";summary.setText(String.format("Collected %d | Unique %d | Scanned %d | Binary %d | Oversized %d | Findings %d | Errors %d%s%s%s",r.collected(),r.unique(),r.scanned(),r.skippedBinary(),r.skippedOversized(),r.findings().size(),r.errors(),r.cancelled()?" | Cancelled":"",retained,dropped));if(r.errors()>0)api.logging().logToError("Scan completed with "+r.errors()+" isolated error(s); HTTP content and secrets were not logged.");}catch(Exception ex){if(causedByOutOfMemory(ex)){api.logging().logToError("Scan stopped because the Burp JVM ran out of heap. Reduce Max body MiB or select fewer traffic sources.");summary.setText("Scan stopped: insufficient Java heap. Reduce Max body MiB or select fewer sources.");}else{api.logging().logToError("Scan failed",ex);summary.setText("Scan failed; see Extension errors");}}finally{scanButton.setEnabled(true);stopButton.setEnabled(false);updateEviction();}}
        };worker.execute();
    }

    private void addRule(){RuleEditorDialog.Result result=RuleEditorDialog.show(this,null,Set.of(ScanArea.values()));if(result!=null)ruleModel.add(result.rule());}
    private void editRule(){int view=ruleTable.getSelectedRow();if(view<0){summary.setText("Select a rule to edit");return;}int row=ruleTable.convertRowIndexToModel(view);RuleEditorDialog.Result result=RuleEditorDialog.show(this,ruleModel.ruleAt(row),ruleModel.areasAt(row));if(result!=null)ruleModel.replace(row,result.rule(),result.areas());}
    private void removeRule(){int view=ruleTable.getSelectedRow();if(view<0){summary.setText("Select a custom rule to delete");return;}int row=ruleTable.convertRowIndexToModel(view);if(!ruleModel.ruleAt(row).custom()){summary.setText("Built-in rules can be disabled but not deleted");return;}ruleModel.remove(row);}
    private void filterFindings(){String value=findingFilter.getText().trim();findingSorter.setRowFilter(value.isEmpty()?null:RowFilter.regexFilter("(?i)"+java.util.regex.Pattern.quote(value)));}

    private void chooseImport(){JFileChooser fc=new JFileChooser();fc.setDialogTitle("Import Burp Logger CSV");if(fc.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;File file=fc.getSelectedFile();importStatus.setText("Importing "+file.getName()+"…");new SwingWorker<LoggerCsvImporter.ImportResult,Void>(){protected LoggerCsvImporter.ImportResult doInBackground(){return new LoggerCsvImporter().importFile(file.toPath(),importedRepository);}protected void done(){try{var r=get();importStatus.setText(String.format("%s: %,d rows / %,d imported / %,d skipped / %,d malformed / %,d duplicate / %,d errors",file.getName(),r.totalRows(),r.imported(),r.skipped(),r.malformed(),r.duplicate(),r.errors().size()));if(!r.errors().isEmpty())api.logging().logToError("Logger CSV imported with "+r.errors().size()+" reported error(s); secret values were not logged.");updateEviction();}catch(Exception e){api.logging().logToError("Logger CSV import failed",e);importStatus.setText("Import failed; see Extension errors");}}}.execute();}
    private void chooseExport(boolean json){if(findingModel.findings().isEmpty()){summary.setText("No findings to export");return;}JFileChooser fc=new JFileChooser();fc.setSelectedFile(new File("sensitive-findings."+(json?"json":"csv")));if(fc.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;Path p=fc.getSelectedFile().toPath();new SwingWorker<Void,Void>(){protected Void doInBackground()throws Exception{if(json)new FindingExporter().json(p,findingModel.findings());else new FindingExporter().csv(p,findingModel.findings());return null;}protected void done(){try{get();summary.setText("Exported "+p);}catch(Exception e){api.logging().logToError("Export failed",e);summary.setText("Export failed; see Extension errors");}}}.execute();}
    private void showFinding(Finding f){try{var t=f.traffic();HttpService svc=HttpService.httpService(t.host(),t.port(),t.tls());if(t.requestLength()>0)requestEditor.setRequest(HttpRequest.httpRequest(svc,ByteArray.byteArray(t.request())));if(t.responseLength()>0)responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(t.response())));}catch(RuntimeException e){api.logging().logToError("Could not render selected HTTP message",e);}details.setText("Rule ID: "+f.ruleId()+"\nType: "+f.type()+"\nCategory: "+f.category()+"\nSeverity: "+f.severity()+"\nConfidence: "+f.confidence()+"\nMatch: "+f.evidence()+"\nURL: "+f.traffic().url()+"\nSection: "+f.location()+"\nField: "+f.fieldName()+"\nDetection path: "+f.detectionPath()+"\nSource: "+f.traffic().source()+" / "+f.traffic().tool()+"\nFirst seen: "+f.firstSeen()+"\nOccurrence count: "+f.occurrences()+(f.traffic().requestLength()==0&&f.traffic().responseLength()==0?"\nRaw message: omitted by scan memory limit":""));details.setCaretPosition(0);}
    private boolean causedByOutOfMemory(Throwable error){for(Throwable current=error;current!=null;current=current.getCause())if(current instanceof OutOfMemoryError)return true;return false;}
    private void updateScanProgress(int done,int total){long now=System.nanoTime();if(done<total&&now-lastProgressUpdate<100_000_000L)return;lastProgressUpdate=now;SwingUtilities.invokeLater(()->{progress.setMaximum(Math.max(1,total));progress.setValue(done);progress.setString(done+" / "+total);});}
    private void updateEviction(){long n=capturedRepository.evicted(),i=importedRepository.evicted();if(n>0||i>0)eviction.setText("Storage limit reached: captured evicted "+n+", imported evicted "+i+".");else eviction.setText("Captured: "+capturedRepository.size()+" ("+formatMiB(capturedRepository.storedBytes())+") | Imported: "+importedRepository.size()+" ("+formatMiB(importedRepository.storedBytes())+")");}
    private String formatMiB(long bytes){return String.format("%.1f MiB",bytes/(1024.0*1024.0));}
    public void shutdown(){cancelled.set(true);if(worker!=null)worker.cancel(true);}
}
