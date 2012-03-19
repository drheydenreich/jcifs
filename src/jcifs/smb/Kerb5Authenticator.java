package jcifs.smb;

import java.security.Key;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import jcifs.Config;
import jcifs.smb.ServerMessageBlock;
import jcifs.smb.Kerb5SessionSetupAndX;
import jcifs.smb.SmbException;
import jcifs.smb.SmbSession;

// >>SmbAuthenticator
/**
 * This class implements SmbExtendedAuthenticator interface to provide Kerberos
 * authentication feature. 
 * 
 * @author Shun
 *
 */
public class Kerb5Authenticator implements SmbExtendedAuthenticator{
    /**
     * This variable represents the FLAGS2 field in SMB Header block. The value
     * is predefined to support KerberosV5 authentication. In order to use 
     * KerberosV5 authentication, user need to set the <code>Config</code> property
     * "jcifs.smb.client.flags2" as this value. For example: 
     * <blockquote><pre>
     * Config.setProperty("jcifs.smb.client.flags2",Kerb5Authenticator.FLAGS2);
     * </pre></blockquote>
     */
    public static final String FLAGS2 = "" + 0xd805;

    /**
     * This variable represents the CAPABILITIES field in SMB_PARAMETERS block. 
     * The value is predefined to support KerberosV5 authentication. In order 
     * to use KerberosV5 authentication, user need to set the <code>Config</code>
     * property "jcifs.smb.client.capabilities" as this value. For example: 
     * <blockquote><pre>
     * Config.setProperty("jcifs.smb.client.capabilities",Kerb5Authenticator.CAPABILITIES);
     * </pre></blockquote>
     */
    public static final String CAPABILITIES = "" + 0x800000d4;
    
    private static final String SERVICE = "cifs";
    
    private Subject subject = null;
    private String user = null;
    private String service = SERVICE;
    private int userLifetime = GSSCredential.DEFAULT_LIFETIME;
    private int contextLifetime = GSSContext.DEFAULT_LIFETIME;
    
    /**
     * Contruct a <code>Kerb5Authenticator</code> object with <code>Subject</code>
     * which hold TGT retrieved from KDC. If multiple TGT are contained, the 
     * first one will be used to retrieve user principal.
     * 
     * @param subject represents the user who perform Kerberos authentication.
     * It contains tickets retrieve from KDC.
     */
    public Kerb5Authenticator(Subject subject){
        this.subject = subject;
    }
    
    /**
     * Set the user name which is used to setup <code>GSSContext</code>. If null 
     * is set, the default user will be used which is retrieved from the first 
     * TGT found in <code>Subject</code> .
     * 
     * @param name the user name used to setup <code>GSSContext</code>
     */
    public void setUser(String name){
        user = name;
    }
    
    /**
     * Get the <code>Subject</code> object.
     * 
     * @return Subject represents the user who perform Kerberos authentication.
     * It contains the tickets retrieve from KDC.
     */
    public Subject getSubject() {
        return subject;
    }
    
    /**
     * Get the user name which authenticate against to. If the default user
     * is used, Null will be returned.
     * 
     * @return user name
     */
    public String getUser(){
        return this.user; 
    }
    /**
     * Set the service name which is used to setup <code>GSSContext</code>. 
     * Program will use this name to require service ticket from KDC.
     * 
     * @param name the service name used to require service ticket from KDC.
     */
    public void setService(String name){
        service = name;
    }
    /**
     * Get the service name.
     * 
     * @return the service name used to require service ticket from KDC
     */
    public String getService(){
        return this.service; 
    }
    
    /**
     * Get lifetime of current user.
     * 
     * @return the remaining lifetime in seconds. If the default lifetime is 
     * used, this value have no meaning.
     *         
     */
    public int getUserLifeTime(){
        return userLifetime;
    }
    /**
     * Set lifetime of current user.
     * 
     * @param time the lifetime in seconds
     *              
     */
    public void setUserLifeTime(int time){
        userLifetime = time;
    }
    /**
     * Get lifetime of this context. 
     *  
     * @return the remaining lifetime in seconds. If the default lifetime is 
     * used, this value have no meaning.
     */
    public int getLifeTime(){
        return contextLifetime;
    }
    /**
     * Set the lifetime for this context.
     * 
     * @param time the lifetime in seconds
     */
    public void setLifeTime(int time){
        contextLifetime = time;
    }
    
    /* (non-Javadoc)
     * @see jcifs.smb.SmbExtendedAuthenticator#sessionSetup(jcifs.smb.SmbSession, jcifs.smb.ServerMessageBlock, jcifs.smb.ServerMessageBlock)
     */
    public void sessionSetup(
            final SmbSession session, 
            final ServerMessageBlock andx, 
            final ServerMessageBlock andxResponse) throws SmbException {
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction(){
                public Object run() throws Exception{
                    setup(session, andx, andxResponse);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getException() instanceof SmbException) {
                throw (SmbException) e.getException();
            }
            throw new SmbException(e.getMessage(), e.getException());
        }
    }
    private void setup(SmbSession session, ServerMessageBlock andx, ServerMessageBlock andxResponse) throws SmbAuthException, SmbException {
        Kerb5Context context = null;
        SpnegoContext spnego = null;
        try{
            String host = session.transport.address.getHostAddress();
            try{
                host = session.transport.address.getHostName();
            }catch(Throwable e){}
            context = createContext(host);
            spnego = new SpnegoContext(context.getGSSContext());
            
            byte[] token = new byte[0];

            Kerb5SessionSetupAndX request=null;
            Kerb5SessionSetupAndXResponse response = null;
            
            while(!spnego.isEstablished()){
           		token = spnego.initSecContext(token, 0, token.length);
                if(token != null){
                    request = new Kerb5SessionSetupAndX(session, null/*andx*/);
                    request.getSecurityBlob().set(token);
                    response = new Kerb5SessionSetupAndXResponse( andxResponse );
    
//                  if(session.transport.digest == null && 
//                          (session.transport.server.securityMode & 0x0f)!=0){
                        if(session.transport.digest == null && 
                                (session.transport.server.signaturesRequired || 
                                        (session.transport.server.signaturesEnabled && SmbConstants.SIGNPREF))){
                        Key key = context.searchSessionKey(subject);
                        if(key == null){
                            throw new SmbException("Not found the session key."); 
                        }
                        request.digest = new SigningDigest(key.getEncoded());
                    }
    
                    session.transport.send( request, response );
                    session.transport.digest = request.digest;
                    
                    token = response.getSecurityBlob().get();
                }
            }
            session.setUid(response.uid);
            session.setSessionSetup(true);

        }catch (GSSException e) {
            e.printStackTrace();
            throw new SmbException(e.getMessage());
        }finally{
            if(context != null){
                try {context.dispose();} catch (GSSException e) {}
            }
        }
    }
    private Kerb5Context createContext(String host) throws GSSException{
        Kerb5Context kerb5Context = 
            new Kerb5Context(
                host, 
                service, 
                user,
                userLifetime,
                contextLifetime
                ); 
        kerb5Context.getGSSContext().requestAnonymity(false);
        kerb5Context.getGSSContext().requestSequenceDet(false);
        kerb5Context.getGSSContext().requestMutualAuth(false);
        kerb5Context.getGSSContext().requestConf(false);
        kerb5Context.getGSSContext().requestInteg(false);
        kerb5Context.getGSSContext().requestReplayDet(false);
        return kerb5Context;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object arg0) {
        // >> SmbAuthenticator 11062008
        //this method is called from SmbSession
        return this.getSubject()==((Kerb5Authenticator)arg0).getSubject();
//        return false;
         // SmbAuthenticator 11062008<<
    }

    public String getDomain() {
		String realm = "";
		if (subject != null) {
			Set pr=subject.getPrincipals();
	        for (Iterator ite = pr.iterator();ite.hasNext();){
	        	try{
		        	KerberosPrincipal entry = (KerberosPrincipal) ite.next();
		        	realm = entry.getRealm();
		        	break;
	        	}catch (Exception e){
	        		continue;
	        	}
	        }
		}
		if (realm.isEmpty()){
			return getDefaultDomain();
		}
        return realm;
	}
	private String getDefaultDomain(){
        return Config.getProperty("jcifs.smb.client.domain", "?");
	}
	
}
// SmbAuthenticator<<
