import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import com.sun.security.auth.module.Krb5LoginModule;

import jcifs.Config;
import jcifs.smb.Kerb5Authenticator;
import jcifs.smb.SmbFile;
import jcifs.util.LogStream;

/**
 * @author Shun
 *
 */
public class KerberosAuthExample {
    private static String NAME = "";

    private static String PWD = "";

    private static String URL = "";

    private static String KDC = "";
    
    private static String REALM = "";
    
    public static void main(String[] args) throws LoginException {
        if(args.length != 5){
            help();
            return;
        }
        NAME = args[0];
        PWD = args[1];
        URL = args[2];
        KDC = args[3];
        REALM = args[4];

        Config.setProperty("jcifs.smb.client.capabilities",Kerb5Authenticator.CAPABILITIES);
        Config.setProperty("jcifs.smb.client.flags2",Kerb5Authenticator.FLAGS2);
        Config.setProperty("jcifs.smb.client.signingPreferred", "true");
        try {
            // login
            Subject subject = new Subject();
            login(subject);

            // list file
            SmbFile file = new SmbFile(URL, new Kerb5Authenticator(subject));
            SmbFile[] files = file.listFiles();
            for( int i = 0; i < files.length; i++ ) {
                System.out.println( "-->" + files[i].getName() );
                System.out.println("DFS path: " + files[i].getDfsPath());
            }

        } catch (Exception e) {
            e.printStackTrace();
        } 
    }

    public static void login(Subject subject) throws LoginException{
        System.setProperty("java.security.krb5.kdc", KDC);
        System.setProperty("java.security.krb5.realm", REALM);
        
        Map state = new HashMap();
        state.put("javax.security.auth.login.name", NAME);
        state.put("javax.security.auth.login.password", PWD.toCharArray());
    
        Map option = new HashMap();
        option.put("debug", "true");
        option.put("tryFirstPass", "true");
        option.put("useTicketCache", "false");
        option.put("doNotPrompt", "false");
        option.put("storePass", "false");

        Krb5LoginModule login = new Krb5LoginModule();
        login.initialize(subject, null, state, option);
        
        if(login.login()){
            login.commit();
        }
    }
    
    private static void help(){
        System.out.println("Add arguments in the order of:");
        System.out.println("[username] [password] [smb://url] [kdc] [realm]");
    }
}
