package io.github.sensitivescanner.scanner;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class SecretUtils {
    private static final Set<String> PLACEHOLDERS=Set.of("your_api_key","change_me","changeme","example","test","dummy","sample","xxx","xxxx","123456","password","secret","null","undefined","redacted");
    private static final Pattern UUID=Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private SecretUtils(){}
    public static boolean placeholder(String s){String n=s.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_]",""); return PLACEHOLDERS.contains(n)||n.matches("x{4,}")||n.matches("0{6,}");}
    public static boolean commonIdentifier(String s){return UUID.matcher(s).matches()||s.matches("(?i)[0-9a-f]{32}")||s.matches("(?i)[0-9a-f]{64}")||s.matches("[0-9]{16,}");}
    public static double entropy(String s){if(s.isEmpty())return 0;int[] c=new int[256];for(char ch:s.toCharArray())c[ch&255]++;double h=0;for(int n:c)if(n>0){double p=(double)n/s.length();h-=p*(Math.log(p)/Math.log(2));}return h;}
    public static String mask(String s){if(s==null||s.isEmpty())return ""; if(s.contains("BEGIN ")&&s.contains("PRIVATE KEY"))return "-----BEGIN *** PRIVATE KEY-----";int keep=s.length()<12?2:4; if(s.length()<=keep*2)return "*".repeat(s.length());return s.substring(0,keep)+"*".repeat(Math.min(16,s.length()-keep*2))+s.substring(s.length()-keep);}
}
