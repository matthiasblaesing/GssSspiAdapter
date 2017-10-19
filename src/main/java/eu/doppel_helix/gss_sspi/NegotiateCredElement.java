
package eu.doppel_helix.gss_sspi;

import eu.doppel_helix.gss_sspi.internal.util.WinErrorSecMap;
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

public class NegotiateCredElement extends SSPICredElement {
    
    public static NegotiateCredElement aquireCurrentUser(int usage) throws GSSException {
        Sspi.CredHandle phCredential = new Sspi.CredHandle();
        Sspi.TimeStamp ptsExpiry = new Sspi.TimeStamp();
        
        int result = Secur32.INSTANCE.AcquireCredentialsHandle(null,
                "Negotiate",
                gssUsageToSspiUsage(usage),
                null, null, null, null, phCredential, ptsExpiry);
        
        if(result != WinError.SEC_E_OK) {
            throw new GSSException(GSSException.NO_CRED, result, WinErrorSecMap.resolveString(result));
        }
        
        return new NegotiateCredElement(phCredential, usage);
    }

    public static NegotiateCredElement getInstance(final GSSCaller caller, final SSPINameElement name, final int lifetime) throws GSSException {
        final AccessControlContext acc = AccessController.getContext();

        try {
            final GSSCaller realCaller = (caller == GSSCaller.CALLER_UNKNOWN)
                                   ? GSSCaller.CALLER_INITIATE
                                   : caller;
            return AccessController.doPrivileged(new PrivilegedExceptionAction<NegotiateCredElement>() {
                public NegotiateCredElement run() throws Exception {
                    // Try to get ticket from acc's Subject
                    Subject accSubj = Subject.getSubject(acc);
                    for(NegotiateCredElement element: accSubj.getPrivateCredentials(NegotiateCredElement.class)) {
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

    public NegotiateCredElement(Sspi.CredHandle handle, int usage) {
        super(SSPIProvider.SPNEGO_MECH_OID, handle, usage);
    }
}
