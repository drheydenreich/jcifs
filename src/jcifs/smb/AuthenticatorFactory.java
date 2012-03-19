package jcifs.smb;

/**
 * Simple interface for factory classes that create
 * <code>SmbExtendedAuthenticator</code> instances.
 * 
 * @author Tom Klonikowski (drheydenreich.de)
 * 
 */
public interface AuthenticatorFactory {

	SmbExtendedAuthenticator create();

}
