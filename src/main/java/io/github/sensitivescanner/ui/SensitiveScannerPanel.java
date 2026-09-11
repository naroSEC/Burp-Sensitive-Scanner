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
    private final JSpinner maxBody=new JSpinner(new SpinnerNumberModel(2,1,16,1)),decodeDepth=new JSpinner(new SpinnerNumberModel(2,0,5,1)),entropy=new JSpinner(new SpinnerNumberModel(3.5,0.0,8.0,0.1)),maxEntries=new JSpinner(new SpinnerNumberModel(20000,100,500000,100)),scannerThreads=new JSpinner(new SpinnerNumberModel(Math.max(2,Math.min(4,Runtime.getRuntime().availableProcessors()/2)),1,32,1));
    private final JComboBox<Confidence> minConfidence=new JComboBox<>(Confidence.values());
    private final JLabel importStatus=new JLabel("Imported Logger: none"),summary=new JLabel("Ready"),eviction=new JLabel(" "),resultCount=new JLabel("Results: 0");
    private final JProgressBar progress=new JProgressBar();
    private final JButton scanButton=new JButton("Scan Existing Traffic"),stopButton=new JButton("Stop");
    private final FindingTableModel findingModel=new FindingTableModel();
    private final JTable findings=new JTable(findingModel);
    private final TableRowSorter<FindingTableModel> findingSorter=new TableRowSorter<>(findingModel);
    private final JTextField findingFilter=new JTextField(30);
    private final RuleTableModel ruleModel=new RuleTableModel(rules);
    private final JTable ruleTable=new JTable(ruleModel);
    private final TableRowSorter<RuleTableModel> ruleSorter=new TableRowSorter<>(ruleModel);
    private final JTextField ruleFilter=new JTextField(24);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTabbedPane messageTabs=new JTabbedPane();
    private final JTextArea details=new JTextArea();
    private volatile Finding activeFinding;
    private volatile SwingWorker<DetectionEngine.ScanResult,Void> worker;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private volatile long lastProgressUpdate;
    private volatile long scanStartedNanos;

    public SensitiveScannerPanel(MontoyaApi api,TrafficRepository capturedRepository,TrafficRepository importedRepository,TrafficCollector collector){
        super(new BorderLayout(6,6));this.api=api;this.capturedRepository=capturedRepository;this.importedRepository=importedRepository;this.collector=collector;
        requestEditor=api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);responseEditor=api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        setBorder(new EmptyBorder(8,8,8,8));add(buildTabs(),BorderLayout.CENTER);wire();stopButton.setEnabled(false);details.setEditable(false);details.setFont(new Font(Font.MONOSPACED,Font.PLAIN,12));
    }

    private JComponent buildTabs(){JTabbedPane tabs=new JTabbedPane();tabs.addTab("View",buildLogger());tabs.addTab("Options",buildOptions());return tabs;}

    private JComponent buildLogger(){
        findings.setRowSorter(findingSorter);findings.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);findings.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);int[] widths={80,90,190,250,430,140};for(int i=0;i<findings.getColumnCount();i++)findings.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));actions.add(scanButton);actions.add(stopButton);JButton clear=new JButton("Clear Results"),importButton=new JButton("Import Logger CSV"),json=new JButton("Export JSON"),csv=new JButton("Export CSV");actions.add(clear);actions.add(importButton);actions.add(json);actions.add(csv);progress.setStringPainted(true);progress.setPreferredSize(new Dimension(220,24));actions.add(progress);actions.add(summary);clear.addActionListener(e->{findingModel.setFindings(List.of());resultCount.setText("Results: 0");summary.setText("Results cleared");});importButton.addActionListener(e->chooseImport());json.addActionListener(e->chooseExport(true));csv.addActionListener(e->chooseExport(false));
        JPanel filterBar=new JPanel(new FlowLayout(FlowLayout.LEFT));filterBar.add(resultCount);filterBar.add(new JLabel("Filter"));filterBar.add(findingFilter);filterBar.add(importStatus);JPanel findingList=new JPanel(new BorderLayout());findingList.add(filterBar,BorderLayout.NORTH);findingList.add(new JScrollPane(findings),BorderLayout.CENTER);
        messageTabs.addTab("Request",requestEditor.uiComponent());messageTabs.addTab("Response",responseEditor.uiComponent());messageTabs.addTab("Finding Details",new JScrollPane(details));JSplitPane vertical=new JSplitPane(JSplitPane.VERTICAL_SPLIT,findingList,messageTabs);vertical.setResizeWeight(.55);
        JPanel panel=new JPanel(new BorderLayout());panel.add(actions,BorderLayout.NORTH);panel.add(vertical,BorderLayout.CENTER);return panel;
    }

    private JComponent buildOptions(){
        JPanel controls=new JPanel();controls.setLayout(new BoxLayout(controls,BoxLayout.Y_AXIS));
        JPanel sources=new JPanel(new FlowLayout(FlowLayout.LEFT));sources.setBorder(BorderFactory.createTitledBorder("Traffic Sources"));sources.add(proxy);sources.add(siteMap);sources.add(live);sources.add(logger);sources.add(scope);controls.add(sources);
        JPanel areas=new JPanel(new FlowLayout(FlowLayout.LEFT));areas.setBorder(BorderFactory.createTitledBorder("Scan Areas"));areas.add(requestUrl);areas.add(requestHeaders);areas.add(requestBody);areas.add(responseHeaders);areas.add(responseBody);controls.add(areas);
        JPanel scanner=new JPanel(new FlowLayout(FlowLayout.LEFT));scanner.setBorder(BorderFactory.createTitledBorder("Scanner"));scanner.add(new JLabel("Threads"));scanner.add(scannerThreads);scanner.add(new JLabel("Max body MiB"));scanner.add(maxBody);scanner.add(new JLabel("Decode depth"));scanner.add(decodeDepth);scanner.add(new JLabel("Entropy"));scanner.add(entropy);scanner.add(new JLabel("Minimum confidence"));scanner.add(minConfidence);scanner.add(new JLabel("Collector entries"));scanner.add(maxEntries);scanner.add(eviction);controls.add(scanner);
        JPanel panel=new JPanel(new BorderLayout(0,6));panel.add(controls,BorderLayout.NORTH);panel.add(buildRulesPanel(),BorderLayout.CENTER);return panel;
    }

    private JComponent buildRulesPanel(){
        ruleTable.setRowSorter(ruleSorter);ruleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);ruleTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);int[] widths={55,210,130,420,360,80};for(int i=0;i<ruleTable.getColumnCount();i++)ruleTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel buttons=new JPanel(new FlowLayout(FlowLayout.LEFT));JButton add=new JButton("Add Regex"),edit=new JButton("Edit"),remove=new JButton("Delete"),enable=new JButton("Enable All"),disable=new JButton("Disable All");buttons.add(add);buttons.add(edit);buttons.add(remove);buttons.add(enable);buttons.add(disable);buttons.add(Box.createHorizontalStrut(12));buttons.add(new JLabel("Filter rules"));buttons.add(ruleFilter);add.addActionListener(e->addRule());edit.addActionListener(e->editRule());remove.addActionListener(e->removeRule());enable.addActionListener(e->ruleModel.setAll(true));disable.addActionListener(e->ruleModel.setAll(false));
        JPanel panel=new JPanel(new BorderLayout());panel.add(buttons,BorderLayout.NORTH);panel.add(new JScrollPane(ruleTable),BorderLayout.CENTER);return panel;
    }

    private void wire(){
        scanButton.addActionListener(e->startScan());stopButton.addActionListener(e->{cancelled.set(true);summary.setText("Stopping…");});findings.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting()&&findings.getSelectedRow()>=0)showFinding(findingModel.finding(findings.convertRowIndexToModel(findings.getSelectedRow())));});maxEntries.addChangeListener(e->{capturedRepository.setMaxEntries((Integer)maxEntries.getValue());updateEviction();});
        findingFilter.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){filterFindings();}public void removeUpdate(DocumentEvent e){filterFindings();}public void changedUpdate(DocumentEvent e){filterFindings();}});
        ruleFilter.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){filterRules();}public void removeUpdate(DocumentEvent e){filterRules();}public void changedUpdate(DocumentEvent e){filterRules();}});
        messageTabs.addChangeListener(e->{if(messageTabs.getSelectedIndex()==1&&activeFinding!=null)SwingUtilities.invokeLater(()->focusResponseMatch(activeFinding));});
    }

    private ScanSettings settings(){
        ScanSettings s=new ScanSettings();s.maximumBodySize=(Integer)maxBody.getValue()*1024*1024;s.maximumInputSize=s.maximumBodySize+1024*1024;s.maximumDecodedSize=s.maximumBodySize;s.maximumDecodeDepth=(Integer)decodeDepth.getValue();s.scannerThreads=(Integer)scannerThreads.getValue();s.entropyThreshold=(Double)entropy.getValue();s.minimumConfidence=(Confidence)minConfidence.getSelectedItem();s.enabledAreas.clear();if(requestUrl.isSelected())s.enabledAreas.add(ScanArea.REQUEST_URL);if(requestHeaders.isSelected())s.enabledAreas.add(ScanArea.REQUEST_HEADERS);if(requestBody.isSelected())s.enabledAreas.add(ScanArea.REQUEST_BODY);if(responseHeaders.isSelected())s.enabledAreas.add(ScanArea.RESPONSE_HEADERS);if(responseBody.isSelected())s.enabledAreas.add(ScanArea.RESPONSE_BODY);s.scanRequest=requestUrl.isSelected()||requestHeaders.isSelected()||requestBody.isSelected();s.scanResponse=responseHeaders.isSelected()||responseBody.isSelected();ruleModel.apply(s);return s;
    }

    private void startScan(){
        if(worker!=null&&!worker.isDone())return;cancelled.set(false);lastProgressUpdate=0;scanStartedNanos=System.nanoTime();scanButton.setEnabled(false);stopButton.setEnabled(true);progress.setValue(0);summary.setText("Scanning traffic…");ScanSettings settings=settings();DetectionEngine engine=new DetectionEngine(ruleModel.rules());boolean useProxy=proxy.isSelected(),useSiteMap=siteMap.isSelected(),useLive=live.isSelected(),useLogger=logger.isSelected(),inScopeOnly=scope.getSelectedIndex()==0;
        worker=new SwingWorker<>(){
            protected DetectionEngine.ScanResult doInBackground(){DetectionEngine.ScanSession session=engine.newSession(settings,cancelled);TrafficCollector.CollectionResult c=collector.stream(useProxy,useSiteMap,useLive,useLogger,inScopeOnly,settings.maximumInputSize,cancelled,session::accept,SensitiveScannerPanel.this::updateScanProgress);SwingUtilities.invokeLater(()->{progress.setIndeterminate(true);progress.setString("Finishing analysis…");});return session.finish(c.collected(),c.skippedOversized(),c.errors());}
            protected void done(){try{DetectionEngine.ScanResult r=get();findingModel.setFindings(r.findings());resultCount.setText("Results: "+r.findings().size());double seconds=Math.max(.001,(System.nanoTime()-scanStartedNanos)/1_000_000_000.0);String retained=r.omittedRawMessages()>0?" | Raw omitted "+r.omittedRawMessages():"";String dropped=r.droppedFindings()>0?" | Findings capped "+r.droppedFindings():"";summary.setText(String.format("Scanned %d in %.1fs (%.0f/s) | Findings %d | Skipped %d | Errors %d%s%s%s",r.scanned(),seconds,r.scanned()/seconds,r.findings().size(),r.skippedBinary()+r.skippedOversized(),r.errors(),r.cancelled()?" | Cancelled":"",retained,dropped));if(r.errors()>0)api.logging().logToError("Scan completed with "+r.errors()+" isolated error(s); HTTP content and secrets were not logged.");}catch(Exception ex){if(causedByOutOfMemory(ex)){api.logging().logToError("Scan stopped because the Burp JVM ran out of heap. Reduce Max body MiB or select fewer traffic sources.");summary.setText("Scan stopped: insufficient Java heap. Reduce Max body MiB or select fewer sources.");}else{api.logging().logToError("Scan failed",ex);summary.setText("Scan failed; see Extension errors");}}finally{progress.setIndeterminate(false);scanButton.setEnabled(true);stopButton.setEnabled(false);updateEviction();}}
        };worker.execute();
    }

    private void addRule(){RuleEditorDialog.Result result=RuleEditorDialog.show(this,null,Set.of(ScanArea.values()));if(result!=null)ruleModel.add(result.rule());}
    private void editRule(){int view=ruleTable.getSelectedRow();if(view<0){summary.setText("Select a rule to edit");return;}int row=ruleTable.convertRowIndexToModel(view);RuleEditorDialog.Result result=RuleEditorDialog.show(this,ruleModel.ruleAt(row),ruleModel.areasAt(row));if(result!=null)ruleModel.replace(row,result.rule(),result.areas());}
    private void removeRule(){int view=ruleTable.getSelectedRow();if(view<0){summary.setText("Select a custom rule to delete");return;}int row=ruleTable.convertRowIndexToModel(view);if(!ruleModel.ruleAt(row).custom()){summary.setText("Built-in rules can be disabled but not deleted");return;}ruleModel.remove(row);}
    private void filterFindings(){String value=findingFilter.getText().trim();findingSorter.setRowFilter(value.isEmpty()?null:RowFilter.regexFilter("(?i)"+java.util.regex.Pattern.quote(value)));}
    private void filterRules(){String value=ruleFilter.getText().trim();ruleSorter.setRowFilter(value.isEmpty()?null:RowFilter.regexFilter("(?i)"+java.util.regex.Pattern.quote(value)));}

    private void chooseImport(){JFileChooser fc=new JFileChooser();fc.setDialogTitle("Import Burp Logger CSV");if(fc.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;File file=fc.getSelectedFile();importStatus.setText("Importing "+file.getName()+"…");new SwingWorker<LoggerCsvImporter.ImportResult,Void>(){protected LoggerCsvImporter.ImportResult doInBackground(){return new LoggerCsvImporter().importFile(file.toPath(),importedRepository);}protected void done(){try{var r=get();importStatus.setText(String.format("%s: %,d rows / %,d imported / %,d skipped / %,d malformed / %,d duplicate / %,d errors",file.getName(),r.totalRows(),r.imported(),r.skipped(),r.malformed(),r.duplicate(),r.errors().size()));if(!r.errors().isEmpty())api.logging().logToError("Logger CSV imported with "+r.errors().size()+" reported error(s); secret values were not logged.");updateEviction();}catch(Exception e){api.logging().logToError("Logger CSV import failed",e);importStatus.setText("Import failed; see Extension errors");}}}.execute();}
    private void chooseExport(boolean json){if(findingModel.findings().isEmpty()){summary.setText("No findings to export");return;}JFileChooser fc=new JFileChooser();fc.setSelectedFile(new File("sensitive-findings."+(json?"json":"csv")));if(fc.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;Path p=fc.getSelectedFile().toPath();new SwingWorker<Void,Void>(){protected Void doInBackground()throws Exception{if(json)new FindingExporter().json(p,findingModel.findings());else new FindingExporter().csv(p,findingModel.findings());return null;}protected void done(){try{get();summary.setText("Exported "+p);}catch(Exception e){api.logging().logToError("Export failed",e);summary.setText("Export failed; see Extension errors");}}}.execute();}
    private void showFinding(Finding f){activeFinding=f;try{var t=f.traffic();HttpService svc=HttpService.httpService(t.host(),t.port(),t.tls());responseEditor.setSearchExpression("");if(t.requestLength()>0)requestEditor.setRequest(HttpRequest.httpRequest(svc,ByteArray.byteArray(t.request())));if(t.responseLength()>0)responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(t.response())));if(messageTabs.getSelectedIndex()==1)SwingUtilities.invokeLater(()->focusResponseMatch(f));}catch(RuntimeException e){api.logging().logToError("Could not render selected HTTP message",e);}details.setText("Rule ID: "+f.ruleId()+"\nType: "+f.type()+"\nCategory: "+f.category()+"\nSeverity: "+f.severity()+"\nConfidence: "+f.confidence()+"\nMatch: "+f.evidence()+"\nURL: "+f.traffic().url()+"\nSection: "+f.location()+"\nField: "+f.fieldName()+"\nDetection path: "+f.detectionPath()+"\nSource: "+f.traffic().source()+" / "+f.traffic().tool()+"\nFirst seen: "+f.firstSeen()+"\nOccurrence count: "+f.occurrences()+(f.traffic().requestLength()==0&&f.traffic().responseLength()==0?"\nRaw message: omitted by scan memory limit":""));details.setCaretPosition(0);}
    private void focusResponseMatch(Finding finding){if(!isResponseFinding(finding)||finding.traffic().responseLength()==0){responseEditor.setSearchExpression("");return;}try{ResponseMatchLocator.Target target=ResponseMatchLocator.locate(finding.traffic().response(),finding.evidence(),finding.fieldName());if(target==null){responseEditor.setSearchExpression("");return;}responseEditor.setSearchExpression(target.expression());responseEditor.setCaretPosition(target.offset());responseEditor.uiComponent().requestFocusInWindow();}catch(RuntimeException e){api.logging().logToError("Could not focus the detected response match",e);}}
    private boolean isResponseFinding(Finding finding){return switch(finding.location()){case RESPONSE_HEADER,RESPONSE_COOKIE,RESPONSE_BODY,RESPONSE_JAVASCRIPT->true;default->false;};}
    private boolean causedByOutOfMemory(Throwable error){for(Throwable current=error;current!=null;current=current.getCause())if(current instanceof OutOfMemoryError)return true;return false;}
    private void updateScanProgress(int done,int total){long now=System.nanoTime();if(done<total&&now-lastProgressUpdate<100_000_000L)return;lastProgressUpdate=now;SwingUtilities.invokeLater(()->{progress.setMaximum(Math.max(1,total));progress.setValue(done);progress.setString(done+" / "+total);});}
    private void updateEviction(){long n=capturedRepository.evicted(),i=importedRepository.evicted();if(n>0||i>0)eviction.setText("Storage limit reached: captured evicted "+n+", imported evicted "+i+".");else eviction.setText("Captured: "+capturedRepository.size()+" ("+formatMiB(capturedRepository.storedBytes())+") | Imported: "+importedRepository.size()+" ("+formatMiB(importedRepository.storedBytes())+")");}
    private String formatMiB(long bytes){return String.format("%.1f MiB",bytes/(1024.0*1024.0));}
    public void shutdown(){cancelled.set(true);if(worker!=null)worker.cancel(true);}
}
