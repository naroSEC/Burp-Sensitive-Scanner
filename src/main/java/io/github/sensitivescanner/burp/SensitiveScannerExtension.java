package io.github.sensitivescanner.burp;

import burp.api.montoya.*;
import burp.api.montoya.core.Registration;
import io.github.sensitivescanner.traffic.TrafficRepository;
import io.github.sensitivescanner.ui.SensitiveScannerPanel;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

public final class SensitiveScannerExtension implements BurpExtension {
    @Override public void initialize(MontoyaApi api){
        api.extension().setName("Sensitive Scanner");TrafficRepository capturedRepository=new TrafficRepository(20000,64L*1024*1024),importedRepository=new TrafficRepository(500000,128L*1024*1024);AtomicReference<SensitiveScannerPanel> panelRef=new AtomicReference<>();AtomicReference<Registration> tabRef=new AtomicReference<>();
        Registration httpRegistration=api.http().registerHttpHandler(new LiveTrafficCollector(capturedRepository,api.logging()));
        SwingUtilities.invokeLater(()->{try{TrafficCollector collector=new TrafficCollector(api,capturedRepository,importedRepository);SensitiveScannerPanel panel=new SensitiveScannerPanel(api,capturedRepository,importedRepository,collector);panelRef.set(panel);api.userInterface().applyThemeToComponent(panel);tabRef.set(api.userInterface().registerSuiteTab("Sensitive Scanner",panel));}catch(RuntimeException e){api.logging().logToError("Sensitive Scanner UI initialization failed",e);}});
        api.extension().registerUnloadingHandler(()->{httpRegistration.deregister();Registration tab=tabRef.get();if(tab!=null)tab.deregister();SensitiveScannerPanel p=panelRef.get();if(p!=null)p.shutdown();});
        api.logging().logToOutput("Sensitive Scanner loaded. Detection runs only when Scan Existing Traffic is pressed.");
    }
}
