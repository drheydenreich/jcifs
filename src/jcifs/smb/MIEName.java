package jcifs.smb;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

// >>SmbAuthenticator
/**
 * This class is used to parse the name of context initiator and 
 * context acceptor which are retrieved from GSSContext.
 * 
 * @author Shun
 *
 */
class MIEName {
    private static byte[] TOK_ID = {04, 01}; 
    private static int TOK_ID_SIZE = 2;  
    private static int MECH_OID_LEN_SIZE = 2;
    private static int NAME_LEN_SIZE = 4;
    
    private Oid oid;
    private String name;
    
    /**
     * Instance a <code>MIEName</code> object.
     * 
     * @param buf the name of context initiator or acceptor
     */
    MIEName(byte[] buf){
        int i;
        int len;
        if(buf.length<TOK_ID_SIZE+MECH_OID_LEN_SIZE){
            throw new IllegalArgumentException();
        }
        // TOK_ID
        for (i = 0; i < TOK_ID.length; i++) {
            if(TOK_ID[i]!=buf[i]){
                throw new IllegalArgumentException();
            }
        }
        // MECH_OID_LEN
        len = 0xff00 & (buf[i++] << 8);
        len |= 0xff & buf[i++];
        
        // MECH_OID
        if(buf.length<i+len){
            throw new IllegalArgumentException();
        }
        byte[] bo = new byte[len]; 
        System.arraycopy(buf, i, bo, 0, len);
        i += len;
        try{
            oid = new Oid(bo);
        }catch (GSSException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
        
        // NAME_LEN
        if(buf.length<i+NAME_LEN_SIZE){
            throw new IllegalArgumentException();
        }
        len  = 0xff000000 & (buf[i++] << 24);
        len |= 0x00ff0000 & (buf[i++] << 16);
        len |= 0x0000ff00 & (buf[i++] << 8);
        len |= 0x000000ff & buf[i++];
        
        // NAME
        if(buf.length<i+len){
            throw new IllegalArgumentException();
        }
        name = new String(buf, i, len);
        
    }
    
    MIEName(Oid oid, String name){
        this.oid = oid;
        this.name = name;
    }
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object arg0) {
        try{
            MIEName terg = (MIEName) arg0;
            if(oid.equals(terg.oid)&&name.equalsIgnoreCase(terg.name)){
                return true;
            }
        }catch (Throwable e) {}
        return false;
    }
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return oid.hashCode();
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return name;
    }
}
// SmbAuthenticator<<
