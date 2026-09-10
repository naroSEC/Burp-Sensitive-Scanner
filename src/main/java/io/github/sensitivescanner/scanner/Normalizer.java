package io.github.sensitivescanner.scanner;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Normalizer {
    public List<TextArtifact> expand(TextArtifact root, ScanSettings settings) {
        List<TextArtifact> out=new ArrayList<>(); Deque<TextArtifact> q=new ArrayDeque<>(); Set<String> seen=new HashSet<>(); q.add(root);
        while(!q.isEmpty()){
            TextArtifact a=q.remove(); if(a.text()==null||a.text().length()>settings.maximumInputSize||!seen.add(a.text()))continue; out.add(a);
            if(a.depth()>=settings.maximumDecodeDepth)continue;
            add(q,a,urlDecode(a.text()),"URL decoded",settings); add(q,a,htmlDecode(a.text()),"HTML entity decoded",settings);
            add(q,a,jsonUnescape(a.text()),"JSON unescaped",settings);
            String compact=a.text().trim(); if(isBase64Candidate(compact)){
                try { add(q,a,new String(Base64.getDecoder().decode(compact),StandardCharsets.UTF_8),"Base64 decoded",settings); }catch(IllegalArgumentException ignored){}
                try { add(q,a,new String(Base64.getUrlDecoder().decode(pad(compact)),StandardCharsets.UTF_8),"Base64URL decoded",settings); }catch(IllegalArgumentException ignored){}
            }
        } return out;
    }
    private void add(Deque<TextArtifact> q,TextArtifact a,String value,String op,ScanSettings s){if(value!=null&&!value.equals(a.text())&&value.length()<=s.maximumDecodedSize&&printable(value))q.add(new TextArtifact(value,a.location(),a.fieldName(),a.path()+" -> "+op,a.depth()+1));}
    private String urlDecode(String s){try{return s.contains("%")?URLDecoder.decode(s,StandardCharsets.UTF_8):s;}catch(Exception e){return s;}}
    private String htmlDecode(String s){return s.replace("&quot;","\"").replace("&#39;","'").replace("&amp;","&").replace("&lt;","<").replace("&gt;",">");}
    private String jsonUnescape(String s){if(!s.contains("\\"))return s;return s.replace("\\\"","\"").replace("\\/","/").replace("\\n","\n").replace("\\r","\r").replace("\\t","\t").replace("\\\\","\\");}
    private boolean isBase64Candidate(String s){return s.length()>=16&&s.length()<=4*1024*1024&&s.matches("[A-Za-z0-9_+/=-]+")&&(s.length()%4==0||s.indexOf('-')>=0||s.indexOf('_')>=0);}
    private String pad(String s){return s+"=".repeat((4-s.length()%4)%4);}
    private boolean printable(String s){if(s.isEmpty())return false;long good=s.chars().filter(c->c==9||c==10||c==13||c>=32).count();return good>=(long)(s.length()*.85);}
}
