package jcifs.smb;

// >>SmbAuthenticator
/**
 * This class represents the Secrity_Blob in SMB Block and is set to support 
 * kerberos authentication.
 * 
 * @author Shun
 *
 */
class SecurityBlob {
    private byte[] b = new byte[0];
    
    SecurityBlob(){}
    SecurityBlob(byte[] b){
        set(b);
    }
    void set(byte[] b){
        this.b = b==null?new byte[0]:b;
    }
    byte[] get(){
        return this.b;
    }
    int length(){
        if(b==null)return 0;
        return b.length;
    }
    /* (non-Javadoc)
     * @see java.lang.Object#clone()
     */
    protected Object clone() throws CloneNotSupportedException {
        return (SecurityBlob)new SecurityBlob((byte[])this.b.clone());
    }
    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object arg0) {
        try{
            SecurityBlob t = (SecurityBlob)arg0;
            for (int i = 0; i < b.length; i++) {
                if(b[i]!=t.b[i]){
                    return false;
                }
            }
            return true;
        }catch(Throwable e){
            return false;
        }
    }
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return b.hashCode();
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        String ret = "";
        for (int i = 0; i < b.length; i++) {
            int n = b[i] & 0xff;
            if(n<=0x0f){
                ret += "0";
            }
            ret += Integer.toHexString(n);
        }
        return ret;
    }
}
// SmbAuthenticator<<
