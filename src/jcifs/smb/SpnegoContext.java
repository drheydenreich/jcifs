package jcifs.smb;

import java.io.IOException;
import jcifs.spnego.NegTokenInit;
import jcifs.spnego.NegTokenTarg;
import jcifs.spnego.SpnegoToken;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

// >>SmbAuthenticator
/**
 * This class used to wrap a {@link GSSContext} to provide SPNEGO feature.
 * 
 * @author Shun
 *
 */
class SpnegoContext{
    private GSSContext context;
    private Oid[] mechs;
    
    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link GSSContext}
     * with the same mechanism this {@link GSSContext} used.
     * 
     * @param source the {@link GSSContext} to be wrapped
     * @throws GSSException
     */
    SpnegoContext(GSSContext source) throws GSSException{
        this(source, new Oid[]{source.getMech()});
    }
    /**
     * Instance a <code>SpnegoContext</code> object by wrapping a {@link GSSContext}
     * with specified mechanism.
     * 
     * @param source the {@link GSSContext} to be wrapped
     * @param mech  the mechanism is being used for this context.
     */
    SpnegoContext(GSSContext source, Oid[] mech){
        context = source;
        this.mechs = mech;
    }
    /**
     * Determines what mechanism is being used for this context. 
     * 
     * @return the Oid of the mechanism being used
     */
    Oid[] getMechs() {
        return mechs;
    }
    /**
     * Set what mechanism is being used for this context. 
     * 
     * @param mechs
     */
    void setMechs(Oid[] mechs) {
        this.mechs = mechs;
    }
    /**
     * Get the GSSContext initialized for SPNEGO.
     * 
     * @return the gsscontext
     */
    GSSContext getGssContext(){
        return context;
    }
    
    /**
     * Initialize the GSSContext to provide SPNEGO feature.
     * 
     * @param inputBuf
     * @param offset
     * @param len
     * @return
     * @throws GSSException
     */
    byte[] initSecContext(byte[] inputBuf, int offset, int len) throws GSSException {
        byte[] ret = null;
        if(len == 0){
            byte[] mechToken = context.initSecContext(inputBuf, offset, len);
            int contextFlags = 0;
            if (context.getCredDelegState()) {
                contextFlags |= NegTokenInit.DELEGATION;
            }
            if (context.getMutualAuthState()) {
                contextFlags |= NegTokenInit.MUTUAL_AUTHENTICATION;
            }
            if (context.getReplayDetState()) {
                contextFlags |= NegTokenInit.REPLAY_DETECTION;
            }
            if (context.getSequenceDetState()) {
                contextFlags |= NegTokenInit.SEQUENCE_CHECKING;
            }
            if (context.getAnonymityState()) {
                contextFlags |= NegTokenInit.ANONYMITY;
            }
            if (context.getConfState()) {
                contextFlags |= NegTokenInit.CONFIDENTIALITY;
            }
            if (context.getIntegState()) {
                contextFlags |= NegTokenInit.INTEGRITY;
            }
            ret = new NegTokenInit(new String[]{context.getMech().toString()}, contextFlags, mechToken, null).toByteArray();
        }else{
            SpnegoToken spToken = getToken(inputBuf, offset, len);
            byte[] mechToken = spToken.getMechanismToken();
            mechToken = context.initSecContext(
                    mechToken, 
                        0, mechToken.length);
            if(mechToken!=null){
                int result = NegTokenTarg.ACCEPT_INCOMPLETE;
                if(context.isEstablished()){
                    result = NegTokenTarg.ACCEPT_COMPLETED;
                }
                ret = new NegTokenTarg(result, context.getMech().toString(), mechToken, null).toByteArray();
            }
        }
        return ret;
    }
    
    /**
     * 
     * 
     * @return
     */
    public boolean isEstablished() {
        return context.isEstablished();
    }
    
    private SpnegoToken getToken(byte[] token, int off, int len) throws GSSException{
        byte[] b = new byte[len];
        if(off==0 && token.length==len){
            b = token;
        }else{
            System.arraycopy(token, off, b, 0, len);
        }
        return getToken(b);
    }
    private SpnegoToken getToken(byte[] token) throws GSSException{
        SpnegoToken spnegoToken = null;
        try{
            switch (token[0]) {
            case (byte) 0x60:
                spnegoToken = new NegTokenInit(token);
                break;
            case (byte) 0xa1:
                spnegoToken = new NegTokenTarg(token);
                break;
            default:
                throw new GSSException(GSSException.DEFECTIVE_TOKEN);   
            }
            return spnegoToken;
        }catch (IOException e) {
            throw new GSSException(GSSException.FAILURE);
        }
    }
}
// SmbAuthenticator<<
