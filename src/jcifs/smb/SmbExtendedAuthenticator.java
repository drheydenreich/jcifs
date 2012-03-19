// >>SmbAuthenticator
package jcifs.smb;

/**
 * This interface is used to support kinds of Extended Security Authentication. 
 */
public interface SmbExtendedAuthenticator {
    /**
     * Setup a session.
     * 
     * @param session 
     * @param andx 
     * @param andxResponse 
     * @throws SmbException 
     */
    public void sessionSetup(
            SmbSession session,
            ServerMessageBlock andx,
            ServerMessageBlock andxResponse     
    )throws SmbException;
    
    public String getDomain();
}
// SmbAuthenticator<<
