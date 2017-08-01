
package eu.doppel_helix.gss_sspi;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

public class NTLMMechFactory extends SSPIMechFactory {

    public NTLMMechFactory(GSSCaller caller) {
        super(SSPIProvider.NTML_MECH_OID, caller);
    }

    @Override
    public GSSCredentialSpi getCredentialElement(GSSNameSpi name, int initLifetime, int acceptLifetime, int usage) throws GSSException {
        if (name != null && !(name instanceof SSPINameElement)) {
            name = SSPINameElement.getInstance(name.toString(),
                    name.getStringNameType());
        }

        
        NTLMCredElement credElement = SSPIMechFactory.getCredFromSubject(name, (usage != GSSCredential.ACCEPT_ONLY), getMechanismOid(), NTLMCredElement.class);

        if (credElement == null) {
            if (usage == GSSCredential.INITIATE_ONLY || usage
                    == GSSCredential.INITIATE_AND_ACCEPT) {
                credElement = NTLMCredElement.getInstance(caller, (SSPINameElement) name, initLifetime);
                checkInitCredPermission((SSPINameElement) credElement.getName());
            } else if (usage == GSSCredential.ACCEPT_ONLY) {
                credElement = NTLMCredElement.getInstance(caller, (SSPINameElement) name, acceptLifetime);
                checkAcceptCredPermission((SSPINameElement) credElement.getName(), name);
            } else {
                throw new GSSException(GSSException.FAILURE, -1,
                        "Unknown usage mode requested");
            }
        }
        return credElement;
    }

    @Override
    public GSSContextSpi getMechanismContext(GSSNameSpi peer, GSSCredentialSpi myInitiatorCred, int lifetime) throws GSSException {
        return new NTLMContext(caller, (SSPINameElement) peer, (NTLMCredElement) myInitiatorCred, lifetime);
    }

    @Override
    public GSSContextSpi getMechanismContext(GSSCredentialSpi myAcceptorCred) throws GSSException {
        return new NTLMContext(caller,(NTLMCredElement) myAcceptorCred);
    }

    @Override
    public GSSContextSpi getMechanismContext(byte[] exportedContext) throws GSSException {
        return new NTLMContext(caller, exportedContext);
    }

}
