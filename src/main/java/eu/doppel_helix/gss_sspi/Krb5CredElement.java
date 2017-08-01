
package eu.doppel_helix.gss_sspi;

import eu.doppel_helix.gss_sspi.util.WinErrorSecMap;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinError;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;

public class Krb5CredElement extends SSPICredElement {
    
    public static Krb5CredElement aquireCurrentUser(int usage) throws GSSException {
        Sspi.CredHandle phCredential = new Sspi.CredHandle();
        Sspi.TimeStamp ptsExpiry = new Sspi.TimeStamp();
        
        int result = Secur32.INSTANCE.AcquireCredentialsHandle(null,
                "Kerberos",
                gssUsageToSspiUsage(usage),
                null, null, null, null, phCredential, ptsExpiry);
        
        if(result != WinError.SEC_E_OK) {
            throw new GSSException(GSSException.NO_CRED, result, WinErrorSecMap.resolveString(result));
        }
        
        return new Krb5CredElement(phCredential, usage);
    }

    public static Krb5CredElement getInstance(final GSSCaller caller, final SSPINameElement name, final int lifetime) throws GSSException {
        final AccessControlContext acc = AccessController.getContext();

        try {
            final GSSCaller realCaller = (caller == GSSCaller.CALLER_UNKNOWN)
                                   ? GSSCaller.CALLER_INITIATE
                                   : caller;
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Krb5CredElement>() {
                public Krb5CredElement run() throws Exception {
                    // Try to get ticket from acc's Subject
                    Subject accSubj = Subject.getSubject(acc);
                    for(Krb5CredElement element: accSubj.getPrivateCredentials(Krb5CredElement.class)) {
                        if(name == null || name.equals(element.getName())) {
                            if(realCaller == GSSCaller.CALLER_INITIATE && element.isInitiatorCredential()) {
                                return element;
                            } else if (realCaller == GSSCaller.CALLER_ACCEPT && element.isAcceptorCredential()) {
                                return element;
                            }
                        }
                    }
                    throw new RuntimeException("No credential Element found");
                }
            });
        } catch (PrivilegedActionException e) {
            GSSException ge =
                new GSSException(GSSException.NO_CRED, -1,
                    "Attempt to obtain new INITIATE credentials failed!" +
                    " (" + e.getMessage() + ")");
            ge.initCause(e.getException());
            throw ge;
        }

    }

    public Krb5CredElement(Sspi.CredHandle handle, int usage) {
        super(SSPIProvider.KRB5_MECH_OID, handle, usage);
    }
}
