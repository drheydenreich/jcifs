package jcifs.smb;

import java.io.UnsupportedEncodingException;

import jcifs.util.LogStream;

// >>SmbAuthenticator
/**
 * This class represents the Session_Setup_AndX_Response command and is set 
 * to support kerberos authentication.
 * 
 * @author Shun
 *
 */
class Kerb5SessionSetupAndXResponse extends AndXServerMessageBlock{
    //private boolean isLoggedInAsGuest;
    private int securityBlobLength = 0;
    
    private SecurityBlob securityBlob = new SecurityBlob();
    private String nativeOs = "";
    private String nativeLanMan = "";
    public Kerb5SessionSetupAndXResponse( ServerMessageBlock andx ){
        super( andx );
    }
    SecurityBlob getSecurityBlob(){
        return securityBlob;
    }
    int writeParameterWordsWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int writeBytesWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int readParameterWordsWireFormat( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;
        //isLoggedInAsGuest = ( buffer[bufferIndex] & 0x01 ) == 0x01 ? true : false;
        bufferIndex+=2;
        securityBlobLength = readInt2(buffer, bufferIndex);
        bufferIndex+=2;
        return bufferIndex - start;
    }
    int readBytesWireFormat( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;
        byte[] b = new byte[securityBlobLength];
        System.arraycopy(buffer, bufferIndex, b, 0, b.length);
        bufferIndex += b.length;
        securityBlob.set(b);
        nativeOs = readString( buffer, bufferIndex );
        bufferIndex += stringWireLength( nativeOs, bufferIndex );

        if( useUnicode ) {
            int len;

            if((( bufferIndex - headerStart ) % 2 ) != 0 ) {
                bufferIndex++;
            }

            len = 0;
            while( buffer[bufferIndex + len] != (byte)0x00 ) {
                len += 2;
                if( len > 256 ) {
                    throw new RuntimeException( "zero termination not found" );
                }
            }
            try {
                nativeLanMan = new String( buffer, bufferIndex, len, "UnicodeLittle" );
            } catch( UnsupportedEncodingException uee ) {
                if( LogStream.level > 1 )
                    uee.printStackTrace( log );
            }
            bufferIndex += len;
        } else {
            nativeLanMan = readString( buffer, bufferIndex );
            bufferIndex += stringWireLength( nativeLanMan, bufferIndex );
        }

        return bufferIndex - start;
    }
    public String toString() {
        String result = new String( "Kerb5SessionSetupAndXResponse[" +
            super.toString() +
            ",nativeOs=" + nativeOs +
            ",nativeLanMan=" + nativeLanMan + "]" );
        return result;
    }
}
// SmbAuthenticator<<
