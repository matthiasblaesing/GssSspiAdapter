/*
 * Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package eu.doppel_helix.gss_sspi;

import eu.doppel_helix.gss_sspi.internal.util.WinErrorSecMap;
import eu.doppel_helix.gss_sspi.internal.util.Secur32X;
import eu.doppel_helix.gss_sspi.internal.util.SspiX;
import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import com.sun.security.jgss.InquireType;
import eu.doppel_helix.gss_sspi.internal.util.SspiX.SecPkgContext_SessionKey;
import eu.doppel_helix.gss_sspi.internal.util.SspiX.SecPkgContext_Sizes;
import java.io.ByteArrayOutputStream;
import org.ietf.jgss.*;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Key;
import javax.security.auth.kerberos.ServicePermission;
import sun.security.jgss.GSSHeader;
import sun.security.util.ObjectIdentifier;

/**
 * Implements the mechanism specific context class for the Kerberos v5
 * GSS-API mechanism.
 *
 * @author Mayank Upadhyay
 * @author Ram Marti
 * @since 1.4
 */
abstract class SSPIContext implements GSSContextSpi {

    /*
     * The different states that this context can be in.
     */

    private static final int STATE_NEW = 1;
    private static final int STATE_IN_PROCESS = 2;
    private static final int STATE_DONE = 3;
    private static final int STATE_DELETED = 4;

    private int state = STATE_NEW;

    public static final int SESSION_KEY = 0;
    public static final int INITIATOR_SUBKEY = 1;
    public static final int ACCEPTOR_SUBKEY = 2;

    /*
     * Optional features that the application can set and their default
     * values.
     */

    private boolean credDelegState  = false;    // now only useful at client
    private boolean mutualAuthState  = true;
    private boolean replayDetState  = true;
    private boolean sequenceDetState  = true;
    private boolean confState  = true;
    private boolean integState  = true;
    private boolean delegPolicyState = false;

    private boolean isConstrainedDelegationTried = false;

    private int keySrc;

    private SSPINameElement myName;
    private SSPINameElement peerName;
    private int lifetime;
    private boolean initiator;
    private ChannelBinding channelBinding;

    private SSPICredElement myCred;
    private SSPICredElement delegatedCred; // Set only on acceptor side

    // XXX See if the required info from these can be extracted and
    // stored elsewhere
    final private GSSCaller caller;
    
    private Sspi.CtxtHandle handle = null;
    private SecPkgContext_Sizes sizes;
    
    /**
     * Constructor for SSPIContext to be called on the context initiator's
     * side.
     */
    SSPIContext(GSSCaller caller, SSPINameElement peerName, SSPICredElement myCred,
                int lifetime)
        throws GSSException {

        if (peerName == null)
            throw new IllegalArgumentException("Cannot have null peer name");
        this.caller = caller != GSSCaller.CALLER_UNKNOWN ? caller : GSSCaller.CALLER_INITIATE;
        this.peerName = peerName;
        this.myCred = myCred;
        this.lifetime = lifetime;
        this.initiator = true;
    }

    /**
     * Constructor for SSPIContext to be called on the context acceptor's
     * side.
     */
    SSPIContext(GSSCaller caller, SSPICredElement myCred)
        throws GSSException {
        this.caller = caller != GSSCaller.CALLER_UNKNOWN ? caller : GSSCaller.CALLER_ACCEPT;
        this.myCred = myCred;
        this.initiator = false;
    }

    /**
     * Constructor for SSPIContext to import a previously exported context.
     */
    public SSPIContext(GSSCaller caller, byte [] interProcessToken)
        throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE,
                               -1, "GSS Import Context not available");
    }

    /**
     * Method to determine if the context can be exported and then
     * re-imported.
     */
    @Override
    public final boolean isTransferable() throws GSSException {
        return false;
    }

    /**
     * The lifetime remaining for this context.
     */
    @Override
    public final int getLifetime() {
        // XXX Return service ticket lifetime
        return GSSContext.INDEFINITE_LIFETIME;
    }

    /*
     * Methods that may be invoked by the GSS framework in response
     * to an application request for setting/getting these
     * properties.
     *
     * These can only be called on the initiator side.
     *
     * Notice that an application can only request these
     * properties. The mechanism may or may not support them. The
     * application must make getXXX calls after context establishment
     * to see if the mechanism implementations on both sides support
     * these features. requestAnonymity is an exception where the
     * application will want to call getAnonymityState prior to sending any
     * GSS token during context establishment.
     *
     * Also note that the requests can only be placed before context
     * establishment starts. i.e. when state is STATE_NEW
     */

    /**
     * Requests the desired lifetime. Can only be used on the context
     * initiator's side.
     */
    @Override
    public void requestLifetime(int lifetime) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            this.lifetime = lifetime;
    }

    /**
     * Requests that confidentiality be available.
     */
    @Override
    public final void requestConf(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            confState  = value;
    }

    /**
     * Is confidentiality available?
     */
    @Override
    public final boolean getConfState() {
        return confState;
    }

    /**
     * Requests that integrity be available.
     */
    @Override
    public final void requestInteg(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            integState  = value;
    }

    /**
     * Is integrity available?
     */
    @Override
    public final boolean getIntegState() {
        return integState;
    }

    /**
     * Requests that credential delegation be done during context
     * establishment.
     */
    @Override
    public final void requestCredDeleg(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            credDelegState  = value;
    }

    /**
     * Is credential delegation enabled?
     */
    @Override
    public final boolean getCredDelegState() {
        if (isInitiator()) {
            return credDelegState;
        } else {
            // Server side deleg state is not flagged by credDelegState.
            // It can use constrained delegation.
            tryConstrainedDelegation();
            return delegatedCred != null;
        }
    }

    /**
     * Requests that mutual authentication be done during context
     * establishment. Since this is fromm the client's perspective, it
     * essentially requests that the server be authenticated.
     */
    @Override
    public final void requestMutualAuth(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator()) {
            mutualAuthState  = value;
        }
    }

    /**
     * Is mutual authentication enabled? Since this is from the client's
     * perspective, it essentially meas that the server is being
     * authenticated.
     */
    @Override
    public final boolean getMutualAuthState() {
        return mutualAuthState;
    }

    /**
     * Requests that replay detection be done on the GSS wrap and MIC
     * tokens.
     */
    @Override
    public final void requestReplayDet(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            replayDetState  = value;
    }

    /**
     * Is replay detection enabled on the GSS wrap and MIC tokens?
     * We enable replay detection if sequence checking is enabled.
     */
    @Override
    public final boolean getReplayDetState() {
        return replayDetState || sequenceDetState;
    }

    /**
     * Requests that sequence checking be done on the GSS wrap and MIC
     * tokens.
     */
    @Override
    public final void requestSequenceDet(boolean value) throws GSSException {
        if (state == STATE_NEW && isInitiator())
            sequenceDetState  = value;
    }

    /**
     * Is sequence checking enabled on the GSS Wrap and MIC tokens?
     * We enable sequence checking if replay detection is enabled.
     */
    @Override
    public final boolean getSequenceDetState() {
        return sequenceDetState || replayDetState;
    }

    /**
     * Requests that the deleg policy be respected.
     */
    @Override
    public final void requestDelegPolicy(boolean value) {
        if (state == STATE_NEW && isInitiator())
            delegPolicyState = value;
    }

    /**
     * Is deleg policy respected?
     */
    @Override
    public final boolean getDelegPolicyState() {
        return delegPolicyState;
    }

    /*
     * Anonymity is a little different in that after an application
     * requests anonymity it will want to know whether the mechanism
     * can support it or not, prior to sending any tokens across for
     * context establishment. Since this is from the initiator's
     * perspective, it essentially requests that the initiator be
     * anonymous.
     */

    @Override
    public final void requestAnonymity(boolean value) throws GSSException {
        // Ignore silently. Application will check back with
        // getAnonymityState.
    }

    // RFC 2853 actually calls for this to be called after context
    // establishment to get the right answer, but that is
    // incorrect. The application may not want to send over any
    // tokens if anonymity is not available.
    @Override
    public final boolean getAnonymityState() {
        return false;
    }

    public final int getKeySrc() {
        return keySrc;
    }

    /**
     * Called on the acceptor side to store the delegated credentials
     * received in the AcceptSecContextToken.
     */
    final void setDelegCred(SSPICredElement delegatedCred) {
        this.delegatedCred = delegatedCred;
    }

    /*
     * While the application can only request the following features,
     * other classes in the package can call the actual set methods
     * for them. They are called as context establishment tokens are
     * received on an acceptor side and the context feature list that
     * the initiator wants becomes known.
     */

    /*
     * This method is also called by InitialToken.OverloadedChecksum if the
     * TGT is not forwardable and the user requested delegation.
     */
    final void setCredDelegState(boolean state) {
        credDelegState = state;
    }

    final void setMutualAuthState(boolean state) {
        mutualAuthState = state;
    }

    final void setReplayDetState(boolean state) {
        replayDetState = state;
    }

    final void setSequenceDetState(boolean state) {
        sequenceDetState = state;
    }

    final void setConfState(boolean state) {
        confState = state;
    }

    final void setIntegState(boolean state) {
        integState = state;
    }

    final void setDelegPolicyState(boolean state) {
        delegPolicyState = state;
    }

    /**
     * Sets the channel bindings to be used during context
     * establishment.
     */
    @Override
    public final void setChannelBinding(ChannelBinding channelBinding)
        throws GSSException {
        this.channelBinding = channelBinding;
    }

    final ChannelBinding getChannelBinding() {
        return channelBinding;
    }

    /**
     * Returns the context initiator name.
     *
     * @return initiator name
     * @exception GSSException
     */
    @Override
    public final GSSNameSpi getSrcName() throws GSSException {
        return (isInitiator()? myName : peerName);
    }

    /**
     * Returns the context acceptor.
     *
     * @return context acceptor(target) name
     * @exception GSSException
     */
    @Override
    public final GSSNameSpi getTargName() throws GSSException {
        return (!isInitiator()? myName : peerName);
    }

    /**
     * Returns the delegated credential for the context. This
     * is an optional feature of contexts which not all
     * mechanisms will support. A context can be requested to
     * support credential delegation by using the <b>CRED_DELEG</b>,
     * or it can request for a constrained delegation.
     * This is only valid on the acceptor side of the context.
     * @return GSSCredentialSpi object for the delegated credential
     * @exception GSSException
     * @see GSSContext#getDelegCredState
     */
    @Override
    public final GSSCredentialSpi getDelegCred() throws GSSException {
        if (state != STATE_IN_PROCESS && state != STATE_DONE)
            throw new GSSException(GSSException.NO_CONTEXT);
        if (isInitiator()) {
            throw new GSSException(GSSException.NO_CRED);
        }
        tryConstrainedDelegation();
        if (delegatedCred == null) {
            throw new GSSException(GSSException.NO_CRED);
        }
        return delegatedCred;
    }

    private void tryConstrainedDelegation() {
        if (state != STATE_IN_PROCESS && state != STATE_DONE) {
            return;
        }
        // We will only try constrained delegation once (if necessary).
        if (!isConstrainedDelegationTried) {
            if (delegatedCred == null) {
                if (SSPIProvider.DEBUG) {
                    System.out.println(">>> Constrained deleg from " + caller);
                }
                // The constrained delegation part. The acceptor needs to have
                // isInitiator=true in order to get a TGT, either earlier at
                // logon stage, if useSubjectCredsOnly, or now.
//  @todo recheck
//                try {
//                    delegatedCred = new Krb5ProxyCredential(
//                        Krb5InitCredential.getInstance(
//                            GSSCaller.CALLER_ACCEPT, myName, lifetime),
//                        peerName, serviceTicket);
//                } catch (GSSException gsse) {
//                    // OK, delegatedCred is null then
//                }
            }
            isConstrainedDelegationTried = true;
        }
    }
    /**
     * Tests if this is the initiator side of the context.
     *
     * @return boolean indicating if this is initiator (true)
     *  or target (false)
     */
    @Override
    public final boolean isInitiator() {
        return initiator;
    }

    /**
     * Tests if the context can be used for per-message service.
     * Context may allow the calls to the per-message service
     * functions before being fully established.
     *
     * @return boolean indicating if per-message methods can
     *  be called.
     */
    @Override
    public final boolean isProtReady() {
        return (state == STATE_DONE);
    }

    private byte[] readFromStream(InputStream is, int length) throws IOException {
        if(length == -1) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[102400];
            int read;
            while(( read = is.read(buffer)) > 0) {
                baos.write(buffer, 0, read);
            }
            return baos.toByteArray();
        } else {
            byte[] buffer = new byte[length];
            is.read(buffer);
            return buffer;
        }
    }
    
    /**
     * Initiator context establishment call. This method may be
     * required to be called several times. A CONTINUE_NEEDED return
     * call indicates that more calls are needed after the next token
     * is received from the peer.
     *
     * @param is contains the token received from the peer. On the
     *  first call it will be ignored.
     * @return any token required to be sent to the peer
     *    It is responsibility of the caller
     *    to send the token to its peer for processing.
     * @exception GSSException
     */
    @Override
    public final byte[] initSecContext(InputStream is, int mechTokenSize)
            throws GSSException {

        byte[] retVal = null;
        int errorCode = GSSException.FAILURE;
        if (SSPIProvider.DEBUG) {
            System.out.println("Entered SSPIContext.initSecContext with "
                    + "state=" + printState(state));
        }
        if (!isInitiator()) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "initSecContext on an acceptor " + "GSSContext");
        }

        try {
            if (state == STATE_NEW || state == STATE_IN_PROCESS) {
                state = STATE_IN_PROCESS;

                errorCode = GSSException.NO_CRED;

                if (myCred == null) {
                        myCred = createCredential(myName);
                } else if (!myCred.isInitiatorCredential()) {
                    throw new GSSException(errorCode, -1,
                            "No TGT available");
                }
                
                if(myCred == null) {
                    throw new GSSException(GSSException.NO_CRED);
                }
                
                myName = (SSPINameElement) myCred.getName();
//                    Credentials tgt;
//                    final Krb5ProxyCredential second;
//                    if (myCred instanceof Krb5InitCredential) {
//                        second = null;
//                        tgt = ((Krb5InitCredential) myCred).getKrb5Credentials();
//                    } else {
//                        second = (Krb5ProxyCredential) myCred;
//                        tgt = second.self.getKrb5Credentials();
//                    }

                checkPermission(peerName.getPrincipalName().getName(),
                        "initiate");

                errorCode = GSSException.FAILURE;

                Sspi.TimeStamp ptsExpiry = new Sspi.TimeStamp();
                IntByReference contextAttr = new IntByReference();

                Sspi.SecBufferDesc reply = null;
                try {
                    byte[] inputToken = readFromStream(is, mechTokenSize);
                    if (inputToken != null && inputToken.length > 0) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                        GSSHeader header = new GSSHeader(new ObjectIdentifier(getMech().toString()), inputToken.length);
//                        header.encode(baos);
                        baos.write(inputToken);
                        reply = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, baos.toByteArray());
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                Sspi.SecBufferDesc desc = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, 64000);

                Sspi.CtxtHandle oldCtx = handle;
                Sspi.CtxtHandle newCtx = handle;
                if (newCtx == null) {
                    newCtx = new Sspi.CtxtHandle();
                }

                int result = Secur32.INSTANCE.InitializeSecurityContext(
                        myCred.getHandle(),
                        oldCtx,
                        this.peerName.getPrincipalName().toString(),
                        stateToContextAttr(),
                        0,
                        0,
                        reply,
                        0,
                        newCtx,
                        desc,
                        contextAttr,
                        ptsExpiry);

                if (result != WinError.SEC_E_OK && result != WinError.SEC_I_CONTINUE_NEEDED) {
                    int majorCode = GSSException.FAILURE;
                    String message = WinErrorSecMap.resolveString(result) + "(" + result + ")";

                    throw new GSSException(majorCode, result, message);
                }
                
                handle = newCtx;

                if(SSPIProvider.DEBUG) {
                    System.out.printf("InitializeSecurityContext-Result: %s (%d)%n",
                            WinErrorSecMap.resolveString(result), result);
                }
                retVal = desc.getBytes();

//                if (resultToken != null && resultToken.length > 0) {
//                    GSSHeader header = new GSSHeader(new ByteArrayInputStream(resultToken));
//                    int tokenLength = header.getMechTokenLength();
//                    int length = resultToken.length;
//                    byte[] newBuffer = new byte[tokenLength];
//                    System.arraycopy(resultToken, length - tokenLength, newBuffer, 0, tokenLength);
//                    retVal = newBuffer;
//                }

                if (SSPIProvider.DEBUG) {
                    if(retVal == null) {
                        System.out.printf("Created InitSecContextToken: NULL%n");
                    } else {
                        System.out.printf("Created InitSecContextToken: %d bytes%n",
                                retVal.length);
                    }
                }
                if (result == WinError.SEC_E_OK) {
                    sizes = new SspiX.SecPkgContext_Sizes();
                    int hresult = Secur32X.INSTANCE.QueryContextAttributes(handle, SspiX.SECPKG_ATTR_SIZES, sizes);
                    if(hresult != WinError.SEC_E_OK) {
                        sizes = null;
                        throw new GSSException(GSSException.DEFECTIVE_CREDENTIAL, hresult, WinErrorSecMap.resolveString(hresult));
                    }
                    stateFromContextAttr(contextAttr.getValue());
                    state = STATE_DONE;
                }
            } else {
                // XXX Use logging API?
                if (SSPIProvider.DEBUG) {
                    System.out.println(state);
                }
            }
        } catch (/* IOException | */ RuntimeException e) {
            GSSException gssException
                    = new GSSException(errorCode, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
        return retVal;
    }

    protected abstract SSPICredElement createCredential(SSPINameElement name) throws GSSException;
    
    private int stateToContextAttr() {
        int ctxParam = Sspi.ISC_REQ_CONNECTION;
        if(this.replayDetState) {
            ctxParam |= Sspi.ISC_REQ_REPLAY_DETECT;
        }
        if(this.mutualAuthState) {
            ctxParam |= Sspi.ISC_REQ_MUTUAL_AUTH;
        }
        if(this.integState) {
            ctxParam |= Sspi.ISC_REQ_INTEGRITY;
        }
        if(this.confState) {
            ctxParam |= Sspi.ISC_REQ_CONFIDENTIALITY;
        }
        if(this.credDelegState) {
            ctxParam |= Sspi.ISC_REQ_DELEGATE;
        }
        if(this.sequenceDetState) {
            ctxParam |= Sspi.ISC_REQ_SEQUENCE_DETECT;
        }
        return ctxParam;
    }
    
    private void stateFromContextAttr(int contextAttr) {
        replayDetState = (contextAttr & Sspi.ISC_REQ_REPLAY_DETECT) > 0;
        mutualAuthState = (contextAttr & Sspi.ISC_REQ_MUTUAL_AUTH) > 0;
        integState = (contextAttr & Sspi.ISC_REQ_INTEGRITY) > 0;
        confState = (contextAttr & Sspi.ISC_REQ_CONFIDENTIALITY) > 0;
        credDelegState = (contextAttr & Sspi.ISC_REQ_DELEGATE) > 0;
        sequenceDetState = (contextAttr & Sspi.ISC_REQ_SEQUENCE_DETECT) > 0;
    }

    @Override
    public final boolean isEstablished() {
        return (state == STATE_DONE);
    }

    /**
     * Acceptor's context establishment call. This method may be
     * required to be called several times. A CONTINUE_NEEDED return
     * call indicates that more calls are needed after the next token
     * is received from the peer.
     *
     * @param is contains the token received from the peer.
     * @return any token required to be sent to the peer
     *    It is responsibility of the caller
     *    to send the token to its peer for processing.
     * @exception GSSException
     */
    @Override
    public final byte[] acceptSecContext(InputStream is, int mechTokenSize)
        throws GSSException {

        byte[] retVal = null;

        if (SSPIProvider.DEBUG) {
            System.out.println("Entered SSPIContext.acceptSecContext with " +
                               "state=" +  printState(state));
        }

        if (isInitiator()) {
            throw new GSSException(GSSException.FAILURE, -1,
                                   "acceptSecContext on an initiator " +
                                   "GSSContext");
        }
        try {
            if (state == STATE_NEW || state == STATE_IN_PROCESS) {
                int oldState = state;
                state = STATE_IN_PROCESS;
                if (myCred == null) {
                    myCred = createCredential(myName);
                } else if (!myCred.isAcceptorCredential()) {
                    throw new GSSException(GSSException.NO_CRED, -1,
                                           "No Secret Key available");
                }
                myName = (SSPINameElement) myCred.getName();

                // If there is already a bound name, check now
                if (myName != null) {
                    SSPIMechFactory.checkAcceptCredPermission(myName, myName);
                }

                Sspi.TimeStamp ptsExpiry = new Sspi.TimeStamp();
                IntByReference contextAttr = new IntByReference();
                
                Sspi.SecBufferDesc reply = null;
                try {
                    byte[] inputToken = readFromStream(is, mechTokenSize);
                    if (inputToken != null && inputToken.length > 0) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        if(oldState == STATE_NEW) {
                            // See eu.doppel_helix.gss_sspi.SSPIProvider.SSPIProvider()
                            // the SSPI should get the full ticket, but does not
                            // for the first package
                            // 
                            // See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8-b132/sun/security/jgss/GSSContextImpl.java#304
                            //
                            // This also causes the NTLM acceptor to fail, as
                            // that ticket is not a GSS package
                            GSSHeader header = new GSSHeader(new ObjectIdentifier(getMech().toString()), inputToken.length);
                            header.encode(baos);
                        }
                        baos.write(inputToken);
                        reply = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, baos.toByteArray());
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                
                Sspi.SecBufferDesc desc = new Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, 64000);

                Sspi.CtxtHandle oldCtx = handle;
                Sspi.CtxtHandle newCtx = handle;
                if (newCtx == null) {
                    newCtx = new Sspi.CtxtHandle();
                }

                int result = Secur32.INSTANCE.AcceptSecurityContext(
                        myCred.getHandle(),
                        oldCtx,
                        reply,
                        stateToContextAttr(),
                        0,
                        newCtx,
                        desc,
                        contextAttr,
                        ptsExpiry);

                if (result != WinError.SEC_E_OK && result != WinError.SEC_I_CONTINUE_NEEDED) {
                    int majorCode = GSSException.FAILURE;
                    String message = WinErrorSecMap.resolveString(result) + "(" + result + ")";

                    throw new GSSException(majorCode, result, message);
                }
                
                handle = newCtx;

                if(SSPIProvider.DEBUG) {
                    System.out.printf("AcceptSecurityContext-Result: %s (%d)%n",
                            WinErrorSecMap.resolveString(result), result);
                }
                retVal = desc.getBytes();

//                if (resultToken != null && resultToken.length > 0) {
//                    GSSHeader header = new GSSHeader(new ByteArrayInputStream(resultToken));
//                    int tokenLength = header.getMechTokenLength();
//                    int length = resultToken.length;
//                    byte[] newBuffer = new byte[tokenLength];
//                    System.arraycopy(resultToken, length - tokenLength, newBuffer, 0, tokenLength);
//                    retVal = newBuffer;
//                }

               if (SSPIProvider.DEBUG) {
                    if(retVal == null) {
                        System.out.printf("Created AcceptSecContextToken: NULL%n");
                    } else {
                        System.out.printf("Created AcceptSecContextToken: %d bytes%n",
                                retVal.length);
                    }
                }
                if (result == WinError.SEC_E_OK) {
                    sizes = new SspiX.SecPkgContext_Sizes();
                    int hresult = Secur32X.INSTANCE.QueryContextAttributes(handle, SspiX.SECPKG_ATTR_SIZES, sizes);
                    if(hresult != WinError.SEC_E_OK) {
                        sizes = null;
                        throw new GSSException(GSSException.DEFECTIVE_CREDENTIAL, hresult, WinErrorSecMap.resolveString(hresult));
                    }
                    stateFromContextAttr(contextAttr.getValue());
                    state = STATE_DONE;
                }
                
            } else  {
                // XXX Use logging API?
                if (SSPIProvider.DEBUG) {
                    System.out.println(state);
                }
            }
        } catch (RuntimeException /* | IOException*/ e) {
            if (SSPIProvider.DEBUG) {
                e.printStackTrace();
            }
            GSSException gssException =
                new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }

        return retVal;
    }

    /**
     * Queries the context for largest data size to accommodate
     * the specified protection and be <= maxTokSize.
     *
     * @param qop the quality of protection that the context will be
     *  asked to provide.
     * @param confReq a flag indicating whether confidentiality will be
     *  requested or not
     * @param outputSize the maximum size of the output token
     * @return the maximum size for the input message that can be
     *  provided to the wrap() method in order to guarantee that these
     *  requirements are met.
     * @throws GSSException
     */
    @Override
    public final int getWrapSizeLimit(int qop, boolean confReq,
                                       int maxTokSize) throws GSSException {

        return maxTokSize - sizes.cbSecurityTrailer - sizes.cbBlockSize;
    }

    @Override
    public final byte[] wrap(byte inBuf[], int offset, int len,
                             MessageProp msgProp) throws GSSException {

        if (SSPIProvider.DEBUG) {
            System.out.println("SSPIContext.wrap: token=[\n"
                    + getHexBytes(inBuf, offset, len)
                    + "]");
        }

        if (state != STATE_DONE) {
            throw new GSSException(GSSException.NO_CONTEXT, -1,
                    " Wrap called in invalid state!");
        }

        SspiX.ManagedSecBufferDesc wrapBuffers = new SspiX.ManagedSecBufferDesc(3);

        Memory wrapMemory = new Memory(len + sizes.cbSecurityTrailer + sizes.cbBlockSize);
        wrapMemory.write(sizes.cbSecurityTrailer, inBuf, offset, len);

        wrapBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        wrapBuffers.getBuffer(0).cbBuffer = sizes.cbSecurityTrailer;
        wrapBuffers.getBuffer(0).pvBuffer = wrapMemory.share(0);
        wrapBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        wrapBuffers.getBuffer(1).cbBuffer = len;
        wrapBuffers.getBuffer(1).pvBuffer = wrapMemory.share(sizes.cbSecurityTrailer);
        wrapBuffers.getBuffer(2).BufferType = SspiX.SECBUFFER_PADDING;
        wrapBuffers.getBuffer(2).cbBuffer = sizes.cbBlockSize;
        wrapBuffers.getBuffer(2).pvBuffer = wrapMemory.share(sizes.cbSecurityTrailer + len);

        int wrapResult = Secur32X.INSTANCE.EncryptMessage(handle, msgProp.getPrivacy() ? 0 : SspiX.SECQOP_WRAP_NO_ENCRYPT, wrapBuffers, 0);

        if(wrapResult != WinError.SEC_E_OK) {
            String errorMessage = WinErrorSecMap.resolveString(wrapResult);
            switch(wrapResult) {
                case WinError.SEC_E_INVALID_HANDLE:
                case WinError.SEC_E_CONTEXT_EXPIRED:
                    throw new GSSException(GSSException.CONTEXT_EXPIRED, wrapResult, errorMessage);
                case WinError.SEC_E_QOP_NOT_SUPPORTED:
                    throw new GSSException(GSSException.BAD_QOP, wrapResult, errorMessage);
                case WinError.SEC_E_BUFFER_TOO_SMALL:
                case WinError.SEC_E_INVALID_TOKEN:
                case WinError.SEC_E_INSUFFICIENT_MEMORY:
                case WinError.SEC_E_CRYPTO_SYSTEM_INVALID:
                default:
                    throw new GSSException(GSSException.FAILURE, wrapResult,errorMessage);
            }
            
        }
        
        byte[] data = new byte[
                wrapBuffers.getBuffer(0).cbBuffer
                + wrapBuffers.getBuffer(1).cbBuffer
                + wrapBuffers.getBuffer(2).cbBuffer
                ];

        wrapBuffers.getBuffer(0).pvBuffer.read(0, data, 0, wrapBuffers.getBuffer(0).cbBuffer);
        wrapBuffers.getBuffer(1).pvBuffer.read(0, data, wrapBuffers.getBuffer(0).cbBuffer, wrapBuffers.getBuffer(1).cbBuffer);
        wrapBuffers.getBuffer(2).pvBuffer.read(0, data, wrapBuffers.getBuffer(0).cbBuffer + wrapBuffers.getBuffer(1).cbBuffer, wrapBuffers.getBuffer(2).cbBuffer);

        if (SSPIProvider.DEBUG) {
            System.out.println("SSPIContext.unwrap: data=["
                    + getHexBytes(data, 0, data.length)
                    + "]");
        }

        return data;
    }

    @Override
    public final void wrap(InputStream is, OutputStream os,
                            MessageProp msgProp) throws GSSException {

        byte[] data;
        try {
            data = new byte[is.available()];
            is.read(data);
            os.write(wrap(data, 0, data.length, msgProp));
        } catch (IOException e) {
            GSSException gssException =
                new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
    }

    @Override
    public final byte[] unwrap(byte inBuf[], int offset, int len,
            MessageProp msgProp)
            throws GSSException {

        if (SSPIProvider.DEBUG) {
            System.out.println("SSPIContext.unwrap: token=["
                    + getHexBytes(inBuf, offset, len)
                    + "]");
        }

        if (state != STATE_DONE) {
            throw new GSSException(GSSException.NO_CONTEXT, -1,
                    " Unwrap called in invalid state!");
        }

        // @todo: Document that unwrap for these Bindings raises a GSSException
        //        if sequence_detection/replay_detection is enabled and 
        //        it was violated
        //        Oracle JDK tollerates sequence fails and still verifies the signature
        SspiX.ManagedSecBufferDesc decryptBuffers = new SspiX.ManagedSecBufferDesc(2);

        Memory wrappedMemory = new Memory(len);
        wrappedMemory.write(0, inBuf, offset, len);

        decryptBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_STREAM;
        decryptBuffers.getBuffer(0).cbBuffer = (int) wrappedMemory.size();
        decryptBuffers.getBuffer(0).pvBuffer = wrappedMemory;
        decryptBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        decryptBuffers.getBuffer(1).cbBuffer = 0;
        decryptBuffers.getBuffer(1).pvBuffer = null;

        IntByReference qop = new IntByReference();
        int unwrapResult = Secur32X.INSTANCE.DecryptMessage(handle, decryptBuffers, 0, qop);

        if(unwrapResult == WinError.SEC_E_OK) {
            msgProp.setQOP(qop.getValue());
            msgProp.setPrivacy(qop.getValue() != SspiX.SECQOP_WRAP_NO_ENCRYPT);
            msgProp.setSupplementaryStates(false, false, false, false, -1, null);
        } else {
            String errorMessage = WinErrorSecMap.resolveString(unwrapResult);
            switch(unwrapResult) {
                case WinError.SEC_E_INCOMPLETE_MESSAGE:
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, unwrapResult, errorMessage);
                case WinError.SEC_E_OUT_OF_SEQUENCE:
                    throw new GSSException(GSSException.BAD_MIC);
                default:
                    throw new GSSException(GSSException.FAILURE, unwrapResult,errorMessage);
            }
            
        }
        
        byte[] data = decryptBuffers.getBuffer(1).getBytes();

        if (SSPIProvider.DEBUG) {
            System.out.println("SSPIContext.unwrap: data=["
                    + getHexBytes(data, 0, data.length)
                    + "]");
        }

        return data;
    }

    @Override
    public final void unwrap(InputStream is, OutputStream os,
                             MessageProp msgProp) throws GSSException {
        try {
            is.mark(sizes.cbSecurityTrailer);
            GSSHeader header = new GSSHeader(is);
            is.reset();
            byte[] buffer = new byte[header.getLength() + header.getMechTokenLength()];
            int read = is.read(buffer);
            if(read != buffer.length) {
                throw new IOException(String.format("Expected: %d byte, received %d bytes", buffer.length, read));
            }
            byte[] unwrappedData = unwrap(buffer, 0, buffer.length, msgProp);
            os.write(unwrappedData);
        } catch (IOException e) {
            GSSException gssException
                    = new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
            
    }

    @Override
    public final byte[] getMIC(byte []inMsg, int offset, int len,
                               MessageProp msgProp)
        throws GSSException {
        
        if (state != STATE_DONE) {
            throw new GSSException(GSSException.NO_CONTEXT, -1,
                    " getMIC called in invalid state!");
        }
        
        SspiX.ManagedSecBufferDesc signBuffers = new SspiX.ManagedSecBufferDesc(2);
        
        Memory signTokenMemory = new Memory(sizes.cbMaxSignature);
        Memory signDataMemory = new Memory(len);
        signDataMemory.write(0, inMsg, offset, len);
        
        signBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
        signBuffers.getBuffer(0).cbBuffer = (int) signTokenMemory.size();
        signBuffers.getBuffer(0).pvBuffer = signTokenMemory;
        signBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
        signBuffers.getBuffer(1).cbBuffer = (int) signDataMemory.size();
        signBuffers.getBuffer(1).pvBuffer = signDataMemory;
        
        int signResult = Secur32X.INSTANCE.MakeSignature(handle, 0, signBuffers, 0);
        
        if(signResult != WinError.SEC_E_OK) {
            String errorMessage = WinErrorSecMap.resolveString(signResult);
            switch(signResult) {
                case WinError.SEC_E_INVALID_HANDLE:
                    throw new GSSException(GSSException.CONTEXT_EXPIRED, signResult, errorMessage);
                case WinError.SEC_E_OUT_OF_SEQUENCE:
                case WinError.SEC_E_INVALID_TOKEN:
                case WinError.SEC_E_NO_AUTHENTICATING_AUTHORITY:
                case WinError.SEC_E_INVALID_PARAMETER:
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, signResult, errorMessage);
                case WinError.SEC_E_QOP_NOT_SUPPORTED:
                    throw new GSSException(GSSException.BAD_QOP, signResult, errorMessage);
                case WinError.SEC_I_RENEGOTIATE:
                default:
                    throw new GSSException(GSSException.FAILURE, signResult, errorMessage);
            }
        }
        
        return signBuffers.getBuffer(0).getBytes();
    }

    private void getMIC(byte[] inMsg, int offset, int len,
                        OutputStream os, MessageProp msgProp)
        throws GSSException {
        try {
            os.write(getMIC(inMsg, offset, len, msgProp));
        } catch (IOException e) {
            GSSException gssException =
                new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
    }

    @Override
    public final void getMIC(InputStream is, OutputStream os,
                              MessageProp msgProp) throws GSSException {
        byte[] data;
        try {
            data = new byte[is.available()];
            is.read(data);
        } catch (IOException e) {
            GSSException gssException =
                new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
        getMIC(data, 0, data.length, os, msgProp);
    }

    @Override
    public final void verifyMIC(byte []inTok, int tokOffset, int tokLen,
                                byte[] inMsg, int msgOffset, int msgLen,
                                MessageProp msgProp)
            throws GSSException {

        if (state != STATE_DONE) {
            throw new GSSException(GSSException.NO_CONTEXT, -1,
                    " verifyMIC called in invalid state!");
        }
        
        Memory verificationMemory = new Memory(tokLen + msgLen);
        verificationMemory.write(0, inTok, tokOffset, tokLen);
        verificationMemory.write(tokLen, inMsg, msgOffset, msgLen);

        SspiX.ManagedSecBufferDesc signVerifyBuffers = new SspiX.ManagedSecBufferDesc(2);
        signVerifyBuffers.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
        signVerifyBuffers.getBuffer(0).pvBuffer = verificationMemory.share(0);
        signVerifyBuffers.getBuffer(0).cbBuffer = tokLen;
        signVerifyBuffers.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
        signVerifyBuffers.getBuffer(1).pvBuffer = verificationMemory.share(tokLen);
        signVerifyBuffers.getBuffer(1).cbBuffer = msgLen;

        // @todo: Document that verifyMIC for these Bindings raises a GSSException
        //        if sequence_detection/replay_detection is enabled and 
        //        it was violated
        //        Oracle JDK tollerates sequence fails and still verifies the signature
        IntByReference qop = new IntByReference();
        int verifyResult = Secur32X.INSTANCE.VerifySignature(handle, signVerifyBuffers, 0, qop);
        
        if(verifyResult == WinError.SEC_E_OK) {
            msgProp.setQOP(qop.getValue());
            msgProp.setPrivacy(false);
            msgProp.setSupplementaryStates(false, false, false, false, -1, null);
        } else {
            String errorMessage = WinErrorSecMap.resolveString(verifyResult);
            switch(verifyResult) {
                case WinError.SEC_E_OUT_OF_SEQUENCE:
                case WinError.SEC_E_MESSAGE_ALTERED:
                    throw new GSSException(GSSException.BAD_MIC, verifyResult, errorMessage);
                case WinError.SEC_E_INVALID_HANDLE:
                    throw new GSSException(GSSException.CONTEXT_EXPIRED, verifyResult, errorMessage);
                case WinError.SEC_E_INVALID_TOKEN:
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN, verifyResult, errorMessage);
                case WinError.SEC_E_QOP_NOT_SUPPORTED:
                    throw new GSSException(GSSException.BAD_QOP, verifyResult, errorMessage);
                default:
                    throw new GSSException(GSSException.FAILURE, verifyResult, errorMessage);
            }
            
        }
    }

    @Override
    public final void verifyMIC(InputStream is, InputStream msgStr,
                                 MessageProp mProp) throws GSSException {
        byte[] msg;
        byte[] token;
        try {
            msg = new byte[msgStr.available()];
            msgStr.read(msg);
            token = new byte[is.available()];
            is.read(token);
        } catch (IOException e) {
            GSSException gssException =
                new GSSException(GSSException.FAILURE, -1, e.getMessage());
            gssException.initCause(e);
            throw gssException;
        }
        verifyMIC(token, 0, token.length, msg, 0, msg.length, mProp);
    }

    /**
     * Produces a token representing this context. After this call
     * the context will no longer be usable until an import is
     * performed on the returned token.
     *
     * @param os the output token will be written to this stream
     * @exception GSSException
     */
    @Override
    public final byte [] export() throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE, -1,
                               "GSS Export Context not available");
    }

    /**
     * Releases context resources and terminates the
     * context between 2 peer.
     *
     * @exception GSSException with major codes NO_CONTEXT, FAILURE.
     */

    @Override
    public final void dispose() throws GSSException {
        state = STATE_DELETED;
        if(handle != null) {
            Secur32X.INSTANCE.DeleteSecurityContext(handle);
            handle = null;
        }
        delegatedCred = null;
    }

    @Override
    public final Provider getProvider() {
        return SSPIProvider.INSTANCE;
    }

    private void checkPermission(String principal, String action) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            ServicePermission perm =
                new ServicePermission(principal, action);
            sm.checkPermission(perm);
        }
    }

    private static String getHexBytes(byte[] bytes, int pos, int len) {

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {

            int b1 = (bytes[i]>>4) & 0x0f;
            int b2 = bytes[i] & 0x0f;

            sb.append(Integer.toHexString(b1));
            sb.append(Integer.toHexString(b2));
            sb.append(' ');
        }
        return sb.toString();
    }

    private static String printState(int state) {
        switch (state) {
          case STATE_NEW:
                return ("STATE_NEW");
          case STATE_IN_PROCESS:
                return ("STATE_IN_PROCESS");
          case STATE_DONE:
                return ("STATE_DONE");
          case STATE_DELETED:
                return ("STATE_DELETED");
          default:
                return ("Unknown state " + state);
        }
    }

    GSSCaller getCaller() {
        // Currently used by InitialToken only
        return caller;
    }

    /**
     * The session key returned by inquireSecContext(KRB5_INQ_SSPI_SESSION_KEY)
     */
    static class SessionKey implements Key {
        private static final long serialVersionUID = 699307378954123869L;

        private final String algorithm;
        private final byte[] key;

        SessionKey(byte[] key, String algorithm) {
            this.key = key;
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return key.clone();
        }

        @Override
        public String toString() {
            return "Session key: etype: " + algorithm + "\n" +
                    new sun.misc.HexDumpEncoder().encodeBuffer(key);
        }
    }

    /**
     * Return the mechanism-specific attribute associated with {@code type}.
     */
    @Override
    public Object inquireSecContext(InquireType type)
            throws GSSException {
        if (!isEstablished()) {
             throw new GSSException(GSSException.NO_CONTEXT, -1,
                     "Security context not established.");
        }
        switch (type) {
            case KRB5_GET_SESSION_KEY:
                SspiX.SecPkgContext_SessionKey keyBuffer = new SecPkgContext_SessionKey();
                SspiX.SecPkgContext_KeyInfo keyInfo = new SspiX.SecPkgContext_KeyInfo();
                try {
                    int result = Secur32X.INSTANCE.QueryContextAttributes(handle, SspiX.SECPKG_ATTR_SESSION_KEY, keyBuffer);
                    if(result != WinError.SEC_E_OK) {
                        throw new GSSException(GSSException.UNAVAILABLE, -1, WinErrorSecMap.resolveString(result));
                    }
                    result = Secur32X.INSTANCE.QueryContextAttributes(handle, SspiX.SECPKG_ATTR_KEY_INFO, keyInfo);
                    if(result != WinError.SEC_E_OK) {
                        throw new GSSException(GSSException.UNAVAILABLE, -1, WinErrorSecMap.resolveString(result));
                    }
                    byte[] rawKey = keyBuffer.getSessionKey();
                    keyBuffer.free();
                    return new SessionKey(rawKey, keyInfo.getEncryptAlgorithmName());
                } finally {
                    keyBuffer.free();
                }
//            case KRB5_GET_TKT_FLAGS:
//                return tktFlags.clone();
//            case KRB5_GET_AUTHZ_DATA:
//                if (isInitiator()) {
//                    throw new GSSException(GSSException.UNAVAILABLE, -1,
//                            "AuthzData not available on initiator side.");
//                } else {
//                    return (authzData==null)?null:authzData.clone();
//                }
//            case KRB5_GET_AUTHTIME:
//                return authTime;//                return new KerberosSessionKey(key);
        }
        throw new GSSException(GSSException.UNAVAILABLE, -1,
                "Inquire type not supported.");
    }
}
