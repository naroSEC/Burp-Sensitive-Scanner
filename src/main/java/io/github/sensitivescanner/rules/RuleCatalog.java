package io.github.sensitivescanner.rules;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.scanner.SecretUtils;
import java.util.*;
import java.util.regex.Pattern;

public final class RuleCatalog {
    private static final int CI=Pattern.CASE_INSENSITIVE|Pattern.MULTILINE;
    public static List<DetectionRule> defaults(){
        List<DetectionRule> r=new ArrayList<>();
        r.add(exact("SENSITIVE-AWS-ACCESS-KEY","AWS Access Key ID","Cloud",Severity.HIGH,"\\b((?:AKIA|ASIA)[A-Z0-9]{16})\\b"));
        r.add(context("SENSITIVE-AWS-SECRET-KEY","AWS Secret Access Key","Cloud",Severity.HIGH,"(?:aws[_ -]?secret(?:[_ -]?access)?[_ -]?key)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9/+=]{40})"));
        r.add(context("SENSITIVE-AWS-SESSION-TOKEN","AWS Session Token","Cloud",Severity.HIGH,"(?:aws[_ -]?session[_ -]?token)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9/+=]{40,})"));
        r.add(exact("SENSITIVE-GOOGLE-API-KEY","Google API Key","Cloud",Severity.HIGH,"\\b(AIza[0-9A-Za-z_-]{35})\\b"));
        r.add(context("SENSITIVE-GCP-SERVICE-ACCOUNT","GCP Service Account Private Key","Cloud",Severity.HIGH,"\"private_key\"\\s*:\\s*\"(-----BEGIN[^\"]+PRIVATE KEY-----[^\"]+)"));
        r.add(context("SENSITIVE-AZURE-CLIENT-SECRET","Azure Client Secret","Cloud",Severity.HIGH,"(?:client[_ -]?secret|azure[_ -]?client[_ -]?secret)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9._~+/-]{16,128})"));
        r.add(exact("SENSITIVE-GITHUB-TOKEN","GitHub Token","Source Control",Severity.HIGH,"\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\\b"));
        r.add(exact("SENSITIVE-GITLAB-TOKEN","GitLab Token","Source Control",Severity.HIGH,"\\b(glpat-[A-Za-z0-9_-]{20,255})\\b"));
        r.add(exact("SENSITIVE-SLACK-TOKEN","Slack Token","SaaS",Severity.HIGH,"\\b(xox[baprs]-[A-Za-z0-9-]{10,200})\\b"));
        r.add(exact("SENSITIVE-STRIPE-SECRET","Stripe Secret Key","SaaS",Severity.HIGH,"\\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\\b"));
        r.add(new RegexRule("SENSITIVE-JWT","JSON Web Token","Authentication","JWT bearer token",Severity.MEDIUM,"\\b(eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{8,})\\b",0,(v,s)->v.split("\\.").length==3?Confidence.HIGH:null));
        r.add(new RegexRule("SENSITIVE-BEARER-TOKEN","Bearer Token","Authentication","Authorization bearer credential",Severity.HIGH,"(?im)^Authorization\\s*:\\s*Bearer\\s+([^\\s]+)",0,(v,s)->validGeneric(v,s)?Confidence.HIGH:null));
        r.add(new RegexRule("SENSITIVE-BASIC-AUTH","Basic Authentication","Authentication","Authorization basic credential",Severity.HIGH,"(?im)^Authorization\\s*:\\s*Basic\\s+([A-Za-z0-9+/=]{8,})",0,(v,s)->Confidence.HIGH));
        r.add(new RegexRule("SENSITIVE-PRIVATE-KEY","Private Key","Cryptographic Key","PEM encoded private key",Severity.HIGH,"(-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]{16,}?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",0,(v,s)->Confidence.HIGH));
        r.add(new RegexRule("SENSITIVE-DATABASE-URI","Database Credential URI","Database","Database URI containing credentials",Severity.HIGH,"\\b((?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|jdbc:[a-z]+)://[^\\s:@/]+:[^\\s@/]+@[^\\s\"']+)",CI,(v,s)->Confidence.HIGH));
        r.add(new RegexRule("SENSITIVE-GENERIC-SECRET","Generic Secret","Generic","Sensitive key paired with a non-placeholder high-entropy value",Severity.MEDIUM,"(?:\"?)(password|passwd|pwd|secret(?:Key|_key)?|api(?:Key|_key|Secret|_secret)|client(?:Secret|_secret)|access(?:Token|_token)|refresh(?:Token|_token)|auth(?:Token|_token)|session(?:Token|_token))(?:\"?)[\\s]*[:=][\\s]*[\"']?([^\"'&\\s,;}]{8,512})",CI,(v,s)->validGeneric(v,s)?(SecretUtils.entropy(v)>=s.entropyThreshold?Confidence.HIGH:Confidence.MEDIUM):null));
        return List.copyOf(r);
    }
    private static RegexRule exact(String id,String n,String c,Severity s,String p){return new RegexRule(id,n,c,"Vendor-specific credential format",s,p,0,(v,x)->Confidence.HIGH);}
    private static RegexRule context(String id,String n,String c,Severity s,String p){return new RegexRule(id,n,c,"Credential identified by key context and value format",s,p,CI,(v,x)->validGeneric(v,x)?Confidence.HIGH:null);}
    private static boolean validGeneric(String v,io.github.sensitivescanner.scanner.ScanSettings s){return v.length()>=8&&!SecretUtils.placeholder(v)&&!SecretUtils.commonIdentifier(v)&&SecretUtils.entropy(v)>=Math.min(3.0,s.entropyThreshold);}
}
