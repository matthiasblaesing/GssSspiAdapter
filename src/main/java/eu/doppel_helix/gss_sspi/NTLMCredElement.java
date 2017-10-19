
package eu.doppel_helix.gss_sspi;

import eu.doppel_helix.gss_sspi.internal.util.WinErrorSecMap;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinError;
import eu.doppel_helix.gss_sspi.internal.util.Secur32X;
import eu.doppel_helix.gss_sspi.internal.util.SspiX;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSNameSpi;

public class NTLMCredElement extends SSPICredElement {
    
    public static NTLMCredElement aquireCurrentUser(int usage) throws GSSException {
        Sspi.CredHandle phCredential = new Sspi.CredHandle();
        Sspi.TimeStamp ptsExpiry = new Sspi.TimeStamp();
        
        int result = Secur32.INSTANCE.AcquireCredentialsHandle(null,
                "NTLM",
                gssUsageToSspiUsage(usage),
                null, null, null, null, phCredential, ptsExpiry);
        
        if(result != WinError.SEC_E_OK) {
            throw new GSSException(GSSException.NO_CRED, result, WinErrorSecMap.resolveString(result));
        }
        
        return new NTLMCredElement(phCredential, usage);
    }

    public static NTLMCredElement getInstance(final GSSCaller caller, final SSPINameElement name, final int lifetime) throws GSSException {
        final AccessControlContext acc = AccessController.getContext();

        try {
            final GSSCaller realCaller = (caller == GSSCaller.CALLER_UNKNOWN)
                                   ? GSSCaller.CALLER_INITIATE
                                   : caller;
            return AccessController.doPrivileged(new PrivilegedExceptionAction<NTLMCredElement>() {
                public NTLMCredElement run() throws Exception {
                    // Try to get ticket from acc's Subject
                    Subject accSubj = Subject.getSubject(acc);
                    for(NTLMCredElement element: accSubj.getPrivateCredentials(NTLMCredElement.class)) {
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

    public NTLMCredElement(Sspi.CredHandle handle, int usage) {
        super(SSPIProvider.NTML_MECH_OID, handle, usage);
    }
    
    @Override
    public GSSNameSpi getName() throws GSSException {
        SspiX.SecPkgCredentials_Names names = new SspiX.SecPkgCredentials_Names();
        int result = Secur32X.INSTANCE.QueryCredentialsAttributes(getHandle(), SspiX.SECPKG_CRED_ATTR_NAMES, names);
        if(result == WinError.SEC_E_OK) {
            String username = names.getUserName();
            names.free();
            // This is a hack and needs to be revisited!
            String[] usernameParts = username.split("\\\\");
            return SSPINameElement.getInstance(usernameParts[1] + "@" + usernameParts[0], null);
        } else {
            throw new GSSException(GSSException.UNAVAILABLE, result, WinErrorSecMap.resolveString(result));
        }
    }
}
