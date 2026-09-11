package io.github.sensitivescanner.ui;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

final class ResponseMatchLocator {
    record Target(String expression,int offset){}

    static Target locate(byte[] response,String evidence,String fieldName){
        String value=evidence==null?"":evidence;
        int truncated=value.indexOf("\n[match truncated at ");
        if(truncated>=0)value=value.substring(0,truncated);
        List<String> candidates=new ArrayList<>();
        if(!value.isEmpty()){
            candidates.add(value);
            candidates.add(URLEncoder.encode(value,StandardCharsets.UTF_8));
            candidates.add(URLEncoder.encode(value,StandardCharsets.UTF_8).replace("+","%20"));
            candidates.add(value.replace("\\","\\\\").replace("\"","\\\""));
            candidates.add(value.replace("&","&amp;").replace("\"","&quot;").replace("'","&#39;").replace("<","&lt;").replace(">","&gt;"));
            byte[] valueBytes=value.getBytes(StandardCharsets.UTF_8);
            candidates.add(Base64.getEncoder().encodeToString(valueBytes));
            candidates.add(Base64.getUrlEncoder().withoutPadding().encodeToString(valueBytes));
        }
        if(fieldName!=null&&!fieldName.isBlank())candidates.add(fieldName);
        for(String candidate:candidates){
            if(candidate.isEmpty())continue;
            String expression=searchExpression(candidate);
            int offset=indexOf(response,expression.getBytes(StandardCharsets.UTF_8));
            if(offset>=0)return new Target(expression,offset);
        }
        return null;
    }

    private static String searchExpression(String value){int line=value.indexOf('\n');int limit=line>0?Math.min(line,512):Math.min(value.length(),512);return value.substring(0,limit);}
    private static int indexOf(byte[] data,byte[] needle){if(needle.length==0)return-1;outer:for(int i=0;i<=data.length-needle.length;i++){for(int j=0;j<needle.length;j++)if(data[i+j]!=needle[j])continue outer;return i;}return-1;}
}
