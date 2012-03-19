package jcifs.smb;

import java.security.AccessController;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

/**
 * <p>
 * Creates <code>Kerb5Authenticator</code> instances using the
 * <code>Subject</code> from the current <code>AccessControlContext</code>.
 * </p>
 * 
 * <p>
 * When setting <code>jcifs.smb.client.authenticatorFactoryClass</code> to this
 * classname, you don't have to worry about special <code>SmbFile</code>
 * constructors when using Kerberos authentication and executing the code as the
 * required subject ( <code>Subject.doAs</code>) - just do
 * <code>new SmbFile(path)</code>.
 * </p>
 * 
 * @author Tom Klonikowski (drheydenreich.de)
 * 
 */
public class Kerb5AuthenticatorFactory implements AuthenticatorFactory {

	public SmbExtendedAuthenticator create() {
		Subject s = Subject.getSubject(AccessController
				.getContext());
		return s.getPrivateCredentials(KerberosTicket.class).isEmpty() ? null : new Kerb5Authenticator(s);
	}
}
