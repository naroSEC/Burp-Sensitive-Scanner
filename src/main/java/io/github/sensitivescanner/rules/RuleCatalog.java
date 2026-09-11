package io.github.sensitivescanner.rules;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.scanner.SecretUtils;
import java.util.*;
import java.util.regex.Pattern;

public final class RuleCatalog {
    private static final int CI=Pattern.CASE_INSENSITIVE|Pattern.MULTILINE;
    private static final Set<ScanArea> ALL=Set.of(ScanArea.values());
    private static final Set<ScanArea> URL=Set.of(ScanArea.REQUEST_URL);
    private static final Set<ScanArea> HEADERS=Set.of(ScanArea.REQUEST_HEADERS,ScanArea.RESPONSE_HEADERS);

    public static List<DetectionRule> defaults(){
        List<DetectionRule> r=new ArrayList<>();
        r.add(exact("SENSITIVE-AWS-ACCESS-KEY","AWS Access Key ID","Cloud",Severity.HIGH,"\\b(A(?:BIA|CCA|GPA|IDA|IPA|KIA|NPA|NVA|PKA|ROA|SCA|SIA)[A-Z0-9]{16,17})\\b"));
        r.add(context("SENSITIVE-AWS-SECRET-KEY","AWS Secret Access Key","Cloud",Severity.HIGH,"(?:aws[_ -]?secret(?:[_ -]?access)?[_ -]?key)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9/+=]{40})"));
        r.add(context("SENSITIVE-AWS-SESSION-TOKEN","AWS Session Token","Cloud",Severity.HIGH,"(?:aws[_ -]?session[_ -]?token)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9/+=]{40,})"));
        r.add(exact("SENSITIVE-AMAZON-MWS-TOKEN","Amazon MWS Auth Token","Cloud",Severity.HIGH,"\\b(amzn\\.mws\\.[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\\b"));
        r.add(exact("SENSITIVE-GOOGLE-API-KEY","Google API Key","Cloud",Severity.HIGH,"\\b(AIza[0-9A-Za-z_-]{35})\\b"));
        r.add(exact("SENSITIVE-GOOGLE-OAUTH-TOKEN","Google OAuth Access Token","Cloud",Severity.HIGH,"\\b(ya29\\.[0-9A-Za-z_-]{32,128})\\b"));
        r.add(exact("SENSITIVE-GOOGLE-OAUTH-CLIENT-ID","Google OAuth Client ID","Cloud",Severity.MEDIUM,"\\b([0-9]{1,20}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com)\\b"));
        r.add(exact("SENSITIVE-GOOGLE-OAUTH-CLIENT-SECRET","Google OAuth Client Secret","Cloud",Severity.HIGH,"\\b(GOCSPX-[0-9A-Za-z_-]{28})\\b"));
        r.add(context("SENSITIVE-GCP-SERVICE-ACCOUNT","GCP Service Account Private Key","Cloud",Severity.HIGH,"\"private_key\"\\s*:\\s*\"(-----BEGIN[^\"]+PRIVATE KEY-----[^\"]+)"));
        r.add(context("SENSITIVE-AZURE-CLIENT-SECRET","Azure Client Secret","Cloud",Severity.HIGH,"(?:client[_ -]?secret|azure[_ -]?client[_ -]?secret)[\\s\"']*[:=][\\s\"']*([A-Za-z0-9._~+/-]{16,128})"));
        r.add(exact("SENSITIVE-GITHUB-TOKEN","GitHub Token","Source Control",Severity.HIGH,"\\b((?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}))\\b"));
        r.add(exact("SENSITIVE-GITLAB-TOKEN","GitLab Token","Source Control",Severity.HIGH,"\\b(glpat-[A-Za-z0-9_-]{20,255})\\b"));
        r.add(exact("SENSITIVE-SLACK-TOKEN","Slack Token","SaaS",Severity.HIGH,"\\b(x(?:ox[psboare]|app)(?:-[A-Za-z0-9]{1,64}){1,5})\\b"));
        r.add(exact("SENSITIVE-STRIPE-SECRET","Stripe API Secret Key","Payment",Severity.HIGH,"\\b([sr]k_(?:live|test)_[A-Za-z0-9]{24,})\\b"));
        r.add(exact("SENSITIVE-STRIPE-WEBHOOK","Stripe Webhook Secret","Payment",Severity.HIGH,"\\b(whsec_[A-Za-z0-9]{32,})\\b"));
        r.add(exact("SENSITIVE-SENDGRID-KEY","SendGrid API Key","SaaS",Severity.HIGH,"\\b(SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43})\\b"));
        r.add(exact("SENSITIVE-MAILGUN-KEY","Mailgun API Key","SaaS",Severity.HIGH,"\\b(key-[0-9a-f]{32})\\b"));
        r.add(exact("SENSITIVE-NUGET-KEY","NuGet API Key","Developer Platform",Severity.HIGH,"\\b(oy2[a-z0-9]{43})\\b"));
        r.add(exact("SENSITIVE-SQUARE-TOKEN","Square Token","Payment",Severity.HIGH,"\\b(sq0(?:atp|csp|idp)-[0-9A-Za-z_-]{22,43})\\b"));
        r.add(exact("SENSITIVE-TWILIO-KEY","Twilio API Key","SaaS",Severity.HIGH,"\\b(SK[0-9A-Za-z]{32})\\b"));
        r.add(exact("SENSITIVE-OPENAI-KEY","OpenAI API Key","AI Platform",Severity.HIGH,"\\b(sk-(?:proj-)?[A-Za-z0-9_-]{40,180})\\b"));

        r.add(new RegexRule("SENSITIVE-JWT","JSON Web Token","Authentication","JWT bearer token",Severity.MEDIUM,"\\b(eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{8,})\\b",0,(v,s)->v.split("\\.").length==3?Confidence.HIGH:null));
        r.add(new RegexRule("SENSITIVE-BEARER-TOKEN","Bearer Token","Authentication","Authorization bearer credential",Severity.HIGH,"(?im)^Authorization\\s*:\\s*Bearer\\s+([^\\s]+)",0,(v,s)->validGeneric(v,s)?Confidence.HIGH:null,HEADERS));
        r.add(new RegexRule("SENSITIVE-BASIC-AUTH","Basic Authentication","Authentication","Authorization basic credential",Severity.HIGH,"(?im)^Authorization\\s*:\\s*Basic\\s+([A-Za-z0-9+/=]{8,})",0,(v,s)->Confidence.HIGH,HEADERS));
        r.add(new RegexRule("SENSITIVE-PRIVATE-KEY","Private Key","Cryptographic Key","PEM encoded private key",Severity.HIGH,"(-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]{16,}?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",0,(v,s)->Confidence.HIGH));
        r.add(new RegexRule("SENSITIVE-PEM-BOUNDARY","Certificate or Key Material","Cryptographic Key","PEM certificate or key boundary",Severity.MEDIUM,"(-----BEGIN (?:CERTIFICATE|PUBLIC KEY|PGP (?:PUBLIC|PRIVATE) KEY BLOCK)-----)",0,(v,s)->Confidence.HIGH));
        r.add(info("SENSITIVE-ENCAPSULATION-BOUNDARY","Encoded Data Boundary","Cryptographic Key",Severity.MEDIUM,"(-----BEGIN [A-Z0-9][A-Z0-9 ]{1,62}-----)",ALL));
        r.add(info("SENSITIVE-ENV-REFERENCE","Environment Configuration File","Sensitive File",Severity.MEDIUM,"((?:^|[/\"'])\\.env(?:\\.[A-Za-z0-9_-]+)?(?=$|[?\"'\\s]))",ALL));
        r.add(new RegexRule("SENSITIVE-DATABASE-URI","Database Credential URI","Database","Database URI containing credentials",Severity.HIGH,"\\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqp|jdbc:[a-z]+)://[^\\s:@/]+:[^\\s@/]+@[^\\s\"']+)",CI,(v,s)->Confidence.HIGH));
        r.add(new RegexRule("SENSITIVE-GENERIC-SECRET","Generic Secret","Generic","Sensitive key paired with a non-placeholder high-entropy value",Severity.MEDIUM,"(?:\"?)(?:password|passwd|pwd|secret(?:Key|_key)?|api(?:Key|_key|Secret|_secret)|client(?:Secret|_secret)|access(?:Token|_token)|refresh(?:Token|_token)|auth(?:Token|_token)|session(?:Token|_token))(?:\"?)[\\s]*[:=][\\s]*[\"']?([^\"'&\\s,;}]{8,512})",CI,(v,s)->validGeneric(v,s)?(SecretUtils.entropy(v)>=s.entropyThreshold?Confidence.HIGH:Confidence.MEDIUM):null));

        r.add(info("SENSITIVE-EMAIL","Email Address","Personal Data",Severity.LOW,"\\b([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,190}\\.[A-Z]{2,24})\\b",ALL));
        r.add(info("SENSITIVE-PRIVATE-IP","Private IPv4 Address","Infrastructure",Severity.LOW,"(?<![0-9])((?:10(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}|192\\.168(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){2}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){2}))(?![0-9])",ALL));
        r.add(info("SENSITIVE-SLACK-WEBHOOK","Slack Webhook","Webhook",Severity.HIGH,"(https?://hooks\\.slack\\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{20,64})",ALL));
        r.add(info("SENSITIVE-TEAMS-WEBHOOK","Microsoft Teams Webhook","Webhook",Severity.HIGH,"(https?://(?:outlook\\.office(?:365)?\\.com/webhook|[A-Za-z0-9.-]+\\.webhook\\.office\\.com)/[^\\s\"'<>]+)",ALL));
        r.add(info("SENSITIVE-FIREBASE-URL","Firebase Database URL","Cloud Resource",Severity.MEDIUM,"(https?://[A-Za-z0-9.-]+\\.(?:firebaseio\\.com|firebasedatabase\\.app))",ALL));
        r.add(info("SENSITIVE-S3-BUCKET","AWS S3 Bucket","Cloud Resource",Severity.MEDIUM,"((?:s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]|https?://(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\\.)?s3(?:\\.dualstack|-accelerate|-accesspoint)?(?:\\.[a-z0-9-]+)?\\.amazonaws\\.com))",ALL));
        r.add(info("SENSITIVE-AZURE-BLOB","Azure Blob Storage","Cloud Resource",Severity.MEDIUM,"(https?://[a-z0-9-]{3,63}\\.blob\\.core\\.windows\\.net)",ALL));
        r.add(info("SENSITIVE-GCS-BUCKET","Google Cloud Storage","Cloud Resource",Severity.MEDIUM,"((?:gs://[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|https?://storage\\.googleapis\\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]))",ALL));
        r.add(info("SENSITIVE-AWS-ARN","Amazon Resource Name","Cloud Resource",Severity.LOW,"\\b(arn:aws(?:-(?:cn|us-gov|iso-[bcd]))?:[A-Za-z0-9._/-]{1,63}:(?:[A-Za-z0-9._/-]{0,63}:){2}[A-Za-z0-9:._/-]{1,1023})\\b",ALL));

        addSensitiveFiles(r);
        return List.copyOf(r);
    }

    private static void addSensitiveFiles(List<DetectionRule> rules) {
        String[][] files={
            {"1Password Database","agilekeychain"},{"ASP Configuration","asa"},{"Apple Keychain","keychain"},{"Azure Service Configuration","cscfg"},{"Backup File","bak"},{"Certificate","cer"},{"Certificate","crt"},{"PKCS#7 Certificate","p7b"},
            {"ZIP Archive","zip"},{"TAR Archive","tar"},{"Gzip Archive","gz"},{"Gzip Archive","tgz"},{"RAR Archive","rar"},{"7-Zip Archive","7z"},{"Configuration File","config"},{"Configuration File","conf"},{"Configuration File","ini"},{"Configuration File","properties"},{"Configuration File","yaml"},{"Configuration File","yml"},{"Configuration File","toml"},
            {"Day One Journal","dayone"},{"Word Document","docx"},{"Word Document","doc"},{"Rich Text Document","rtf"},{"Excel Workbook","xlsx"},{"Excel Workbook","xls"},{"CSV Data","csv"},{"GnuCash Database","gnucash"},{"Include File","inc"},{"Java Source","java"},{"Java Keystore","jks"},{"Java Keystore","keystore"},{"KDE Wallet","kwallet"},{"Little Snitch Configuration","xpl"},
            {"Log File","log"},{"BitLocker TPM Password","tpm"},{"BitLocker Recovery Key","bek"},{"Microsoft SQL Database","mdf"},{"SQL Server Compact Database","sdf"},{"Network Capture","pcap"},{"Network Capture","pcapng"},{"Old File","old"},{"OpenVPN Configuration","ovpn"},{"PDF Document","pdf"},
            {"PHP Source","php"},{"PHP Source","php3"},{"PHP Source","php4"},{"PHP Source","php5"},{"PHP Source","phtml"},{"PHP Archive","phar"},{"Password Safe Database","psafe3"},{"PKCS#12 Key Bundle","pkcs12"},{"PKCS#12 Key Bundle","p12"},{"PFX Key Bundle","pfx"},{"PGP Public Keyring","pkr"},{"PGP Secret Keyring","skr"},{"Armored Key Material","asc"},{"PEM Key Material","pem"},{"Private Key","private_key"},{"Private Key","key"},
            {"PowerPoint Presentation","pptx"},{"PowerPoint Presentation","ppt"},{"Python Source","py"},{"Remote Desktop Configuration","rdp"},{"Ruby Source","rb"},{"SQLite Database","sqlite"},{"SQLite Database","sqlite3"},{"Database File","db"},{"SQL Dump","sql"},{"Sequel Pro Bookmark","plist"},
            {"Shell Configuration","exports"},{"Shell Configuration","functions"},{"Shell Configuration","extra"},{"Shell Script","sh"},{"Bash Script","bash"},{"PowerShell Script","ps1"},{"Temporary File","tmp"},{"Terraform Variables","tfvars"},{"Terraform State","tfstate"},{"Text File","txt"},{"Tunnelblick VPN Configuration","tblk"},{"BitLocker Volume","fve"},{"XML File","xml"},
            {"ASP.NET Source","aspx"},{"ASP.NET Handler","ashx"},{"ASP.NET Service","asmx"},{"JSP Source","jsp"},{"JSP Source","jspx"},{"ColdFusion Source","cfm"},{"ColdFusion Component","cfc"},{"Perl Source","pl"},{"Go Source","go"},{"C# Source","cs"},{"Source Map","map"},{"Java Heap Dump","hprof"}
        };
        for(String[] file:files) rules.add(file(file[0],file[1]));
        String[][] names={
            {"Environment File","(?:^|/)\\.env(?:\\.[A-Za-z0-9_-]+)?"},{"Git Configuration","(?:^|/)\\.git/config"},{"Subversion Metadata","(?:^|/)\\.svn/entries"},{"macOS Metadata","(?:^|/)\\.DS_Store"},{"AWS Credentials File","(?:^|/)\\.aws/credentials"},{"Docker Credentials","(?:^|/)\\.docker/config\\.json"},{"NPM Configuration","(?:^|/)\\.npmrc"},{"Python Package Configuration","(?:^|/)\\.pypirc"},{"Netrc Credentials","(?:^|/)\\.netrc"},{"Kubernetes Configuration","(?:^|/)(?:kubeconfig|\\.kube/config)"},{"Composer Credentials","(?:^|/)auth\\.json"},{"Spring Boot Configuration","(?:^|/)application(?:-[A-Za-z0-9_-]+)?\\.(?:properties|ya?ml)"},{"Jenkins Pipeline","(?:^|/)Jenkinsfile"},{"PHP Information Page","(?:^|/)phpinfo\\.php"}
        };
        for(int i=0;i<names.length;i++) rules.add(new RegexRule("SENSITIVE-FILENAME-"+(i+1),names[i][0],"Sensitive File","Sensitive filename exposed through a request URL",Severity.MEDIUM,"(?i)("+names[i][1]+")(?=[?#]|$)",0,(v,s)->Confidence.HIGH,URL));
    }

    private static RegexRule file(String name,String extension){
        String id="SENSITIVE-FILE-"+extension.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+","-");
        return new RegexRule(id,name,"Sensitive File","Potentially sensitive file requested by URL",Severity.MEDIUM,"(?i)(?:^|/)([^/?#]+\\."+Pattern.quote(extension)+")(?=[?#]|$)",0,(v,s)->Confidence.HIGH,URL);
    }
    private static RegexRule exact(String id,String n,String c,Severity s,String p){return new RegexRule(id,n,c,"Vendor-specific credential format",s,p,0,(v,x)->Confidence.HIGH,ALL);}
    private static RegexRule context(String id,String n,String c,Severity s,String p){return new RegexRule(id,n,c,"Credential identified by key context and value format",s,p,CI,(v,x)->validGeneric(v,x)?Confidence.HIGH:null,ALL);}
    private static RegexRule info(String id,String n,String c,Severity s,String p,Set<ScanArea> areas){return new RegexRule(id,n,c,"Sensitive information or infrastructure reference",s,p,CI,(v,x)->Confidence.HIGH,areas);}
    private static boolean validGeneric(String v,io.github.sensitivescanner.scanner.ScanSettings s){return v.length()>=8&&!SecretUtils.placeholder(v)&&!SecretUtils.commonIdentifier(v)&&SecretUtils.entropy(v)>=Math.min(3.0,s.entropyThreshold);}
}
