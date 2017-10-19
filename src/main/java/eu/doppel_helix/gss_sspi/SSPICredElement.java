
package eu.doppel_helix.gss_sspi;

import eu.doppel_helix.gss_sspi.internal.util.WinErrorSecMap;
import eu.doppel_helix.gss_sspi.internal.util.Secur32X;
import eu.doppel_helix.gss_sspi.internal.util.SspiX;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinError;
import java.security.Provider;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

public class SSPICredElement implements GSSCredentialSpi {
    
    private int usage;
    private Sspi.CredHandle handle;
    private Oid mechanism;
    
    protected SSPICredElement(Oid mechanism, Sspi.CredHandle handle, int usage) {
        this.usage = usage;
        this.handle = handle;
        this.mechanism = mechanism;
    }
    
    @Override
    public Provider getProvider() {
        return SSPIProvider.INSTANCE;
    }

    @Override
    public void dispose() throws GSSException {
        Secur32.INSTANCE.FreeCredentialsHandle(handle);
        handle = null;
    }

    @Override
    public GSSNameSpi getName() throws GSSException {
        SspiX.SecPkgCredentials_Names names = new SspiX.SecPkgCredentials_Names();
        int result = Secur32X.INSTANCE.QueryCredentialsAttributes(handle, SspiX.SECPKG_CRED_ATTR_NAMES, names);
        if(result == WinError.SEC_E_OK) {
            String username = names.getUserName();
            names.free();
            return SSPINameElement.getInstance(username, null);
        } else {
            throw new GSSException(GSSException.UNAVAILABLE, result, WinErrorSecMap.resolveString(result));
        }
    }

    @Override
    public int getInitLifetime() throws GSSException {
        return GSSCredential.INDEFINITE_LIFETIME;
    }

    @Override
    public int getAcceptLifetime() throws GSSException {
        return GSSCredential.INDEFINITE_LIFETIME;
    }

    @Override
    public boolean isInitiatorCredential() throws GSSException {
        return (usage == GSSCredential.INITIATE_ONLY || usage == GSSCredential.INITIATE_AND_ACCEPT);
    }

    @Override
    public boolean isAcceptorCredential() throws GSSException {
        return (usage == GSSCredential.ACCEPT_ONLY || usage == GSSCredential.INITIATE_AND_ACCEPT);
    }

    @Override
    public Oid getMechanism() {
        return mechanism;
    }

    @Override
    public GSSCredentialSpi impersonate(GSSNameSpi gssns) throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE, -1,
                               "Krb5CredElement#impersonate not available");
    }

    public Sspi.CredHandle getHandle() {
        return handle;
    }
    
    protected static int gssUsageToSspiUsage(int usage) {
        switch (usage) {
            case GSSCredential.ACCEPT_ONLY:
                return Sspi.SECPKG_CRED_INBOUND;
            case GSSCredential.INITIATE_ONLY:
                return Sspi.SECPKG_CRED_OUTBOUND;
            default:
                return Sspi.SECPKG_CRED_INBOUND | Sspi.SECPKG_CRED_OUTBOUND;
        }
    }
}
