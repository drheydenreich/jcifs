package jcifs.smb;

// >>SmbAuthenticator
/**
 * This class represents the Session_Setup_AndX command and is set to support 
 * kerberos authentication.
 * 
 * @author Shun
 *
 */
class Kerb5SessionSetupAndX extends AndXServerMessageBlock {
    private int sessionKey = 0;
    private SmbSession session;
    private SecurityBlob securityBlob = new SecurityBlob();
    
    Kerb5SessionSetupAndX( SmbSession session, ServerMessageBlock andx ) throws SmbException {
        super( andx );
        command = SMB_COM_SESSION_SETUP_ANDX;
        this.session = session;
    }
    SecurityBlob getSecurityBlob(){
        return this.securityBlob;
    }
    int writeParameterWordsWireFormat( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        writeInt2( session.transport.snd_buf_size, dst, dstIndex );
        dstIndex += 2;
        writeInt2( CAPABILITIES, dst, dstIndex );
        dstIndex += 2;
        writeInt2( SmbConstants.VC_NUMBER, dst, dstIndex );
        dstIndex += 2;
        writeInt4( sessionKey, dst, dstIndex );
        dstIndex += 4;
        writeInt2( securityBlob.length(), dst, dstIndex );
        dstIndex += 2;
        dst[dstIndex++] = (byte)0x00;
        dst[dstIndex++] = (byte)0x00;
        dst[dstIndex++] = (byte)0x00;
        dst[dstIndex++] = (byte)0x00;
        writeInt4( session.transport.capabilities, dst, dstIndex );
        dstIndex += 4;
        return dstIndex - start;
    }
    int writeBytesWireFormat( byte[] dst, int dstIndex ) {
        int start = dstIndex;
        System.arraycopy( securityBlob.get(), 0, dst, dstIndex, securityBlob.length());
        dstIndex += securityBlob.length();
        dstIndex += writeString( SmbTransport.NATIVE_OS==null?"":SmbTransport.NATIVE_OS, dst, dstIndex );
        dstIndex += writeString( SmbTransport.NATIVE_LANMAN==null?"":SmbTransport.NATIVE_LANMAN, dst, dstIndex );
        return dstIndex - start;
    }
    public String toString() {
        String result = new String( "Kerb5SessionSetupAndX[" +
            super.toString() +
            ",snd_buf_size=" + session.transport.snd_buf_size +
            ",maxMpxCount=" + session.transport.maxMpxCount +
            ",VC_NUMBER=" + SmbTransport.VC_NUMBER +
            ",sessionKey=" + sessionKey +
            ",securityBlobLength=" + securityBlob.length() +
            ",capabilities=" + CAPABILITIES +
            ",securityBlob=" + securityBlob.toString()+ 
            ",os=" + SmbTransport.NATIVE_OS +
            ",lanman=" + SmbTransport.NATIVE_LANMAN
            );
        return result;
    }
    int readBytesWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }
    int readParameterWordsWireFormat(byte[] buffer, int bufferIndex) {
        return 0;
    }
}
// SmbAuthenticator<<
