package eu.doppel_helix.dev.kerberostest;

import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.W32Errors;
import eu.doppel_helix.gss_sspi.SSPIProvider;
import eu.doppel_helix.gss_sspi.util.WinErrorSecMap;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import eu.doppel_helix.gss_sspi.util.Secur32X;
import eu.doppel_helix.gss_sspi.util.SspiX;
import eu.doppel_helix.gss_sspi.util.SspiX.ManagedSecBufferDesc;
import java.security.PrivilegedExceptionAction;
import java.security.Security;
import java.util.Date;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class GssSspiTest {

    @Test
    public void testNTLMInitiator() throws Exception {
        testInitiator("test@kdc.konzern.intern", "NTLM", SSPIProvider.NTML_MECH_OID);
    }
    
    @Test
    public void testNegotiateInitiator() throws Exception {
        testInitiator("test@kdc.konzern.intern", "Negotiate", SSPIProvider.SPNEGO_MECH_OID);
    }
    
    @Test
    public void testKerberosInitiator() throws Exception {
        testInitiator("test@kdc.konzern.intern", "Kerberos", SSPIProvider.KRB5_MECH_OID);
    }
    
    @Test
    @Ignore("Not supported on OpenJDK - see comment")
    public void testNTLMAcceptor() throws Exception {
//        Won't work - the NTLM Ticket is not GSS compatible and can't be parsed
//        by GSSHeader (see: http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8-b132/sun/security/jgss/GSSContextImpl.java#306)
        testAcceptor("test@KONZERN.INTERN", "NTLM", SSPIProvider.NTML_MECH_OID);
    }
    
    @Test
    public void testNegotiateAcceptor() throws Exception {
        testAcceptor("test/kdc.konzern.intern@KONZERN.INTERN", "Negotiate", SSPIProvider.SPNEGO_MECH_OID);
    }
    
    @Test
    public void testKerberosAcceptor() throws Exception {
        testAcceptor("test/kdc.konzern.intern@KONZERN.INTERN", "Kerberos", SSPIProvider.KRB5_MECH_OID);
    }
    
    private void testInitiator(final String targetSPN, final String securityPackage, final Oid gssMech) throws Exception {
        Subject credentials = SSPIProvider.createSubjectForCurrentUser(GSSCredential.INITIATE_ONLY);
        Security.insertProviderAt(new SSPIProvider(), 1);

        final Sspi.TimeStamp serverTimestamp = new Sspi.TimeStamp();
        final Sspi.CredHandle serverCred = new Sspi.CredHandle();
        assertOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, securityPackage, SspiX.SECPKG_CRED_INBOUND, null, null, null, null, serverCred, serverTimestamp));
        
        Subject.doAs(credentials, new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                GSSManager gssManager = GSSManager.getInstance();
                GSSName peer = gssManager.createName(targetSPN, GSSName.NT_HOSTBASED_SERVICE);
                GSSContext ctx = gssManager.createContext(peer, gssMech, null, GSSCredential.INDEFINITE_LIFETIME);

                Sspi.CtxtHandle serverCtx = new Sspi.CtxtHandle();
                IntByReference serverContextAttr = new IntByReference();
                int serverRc = W32Errors.SEC_I_CONTINUE_NEEDED;
                byte[] serverReply = new byte[0];
                
                do {
                    byte[] clientToken = ctx.initSecContext(serverReply, 0, serverReply.length);
                    if (serverRc == W32Errors.SEC_I_CONTINUE_NEEDED) {
                        ManagedSecBufferDesc serverToken = new ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
                        ManagedSecBufferDesc pbClientTokenByValue = new ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, clientToken);
                        serverRc = Secur32X.INSTANCE.AcceptSecurityContext(
                                serverCred,
                                serverCtx.isNull() ? null : serverCtx,
                                pbClientTokenByValue,
                                0,
                                Sspi.SECURITY_NATIVE_DREP,
                                serverCtx,
                                serverToken,
                                serverContextAttr,
                                null);

                        if(serverRc != W32Errors.SEC_E_OK && serverRc != W32Errors.SEC_I_CONTINUE_NEEDED) {
                            throw new RuntimeException("AcceptSecurityContext failed: " + WinErrorSecMap.resolveString(serverRc));
                        }
                        
                        if(serverToken.getBuffer(0).cbBuffer > 0) {
                            serverReply = serverToken.getBuffer(0).getBytes();
                        } else {
                            serverReply = new byte[0];
                        }
                    }
                } while (serverRc != W32Errors.SEC_E_OK || (! ctx.isEstablished()));
                
                Assert.assertTrue("Confidentiality not negotiated (Client)", ctx.getConfState());
                assertBitSet("Confidentiality not negotiated (Server)", serverContextAttr.getValue(), SspiX.ISC_REQ_CONFIDENTIALITY);

                Assert.assertTrue("Sequence Detection not negotiated (Client)", ctx.getSequenceDetState());
                assertBitSet("Sequence Detection not negotiated (Server)", serverContextAttr.getValue(), SspiX.ISC_REQ_SEQUENCE_DETECT);
                
                Assert.assertTrue("Replay Detection not negotiated (Client)", ctx.getReplayDetState());
                assertBitSet("Replay Detection not negotiated (Server)", serverContextAttr.getValue(), SspiX.ISC_REQ_REPLAY_DETECT);
                
                SspiX.SecPkgContext_Sizes sizes = new SspiX.SecPkgContext_Sizes();
                assertOk(Secur32X.INSTANCE.QueryContextAttributes(serverCtx, SspiX.SECPKG_ATTR_SIZES, sizes));
                
                byte[] input = ("Hallo Welt - " + new Date()).getBytes();
                
                byte[] wrapped = ctx.wrap(input, 0, input.length, new MessageProp(true));
                
                SSPICommon.printHexDump(wrapped);
                
                Memory wrappedMemory = new Memory(wrapped.length);
                wrappedMemory.write(0, wrapped, 0, wrapped.length);
                
                ManagedSecBufferDesc decodeBuffers = new ManagedSecBufferDesc(2);
                decodeBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_STREAM;
                decodeBuffers.getBuffer(0).pvBuffer = wrappedMemory;
                decodeBuffers.getBuffer(0).cbBuffer = (int) wrappedMemory.size();
                decodeBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
                decodeBuffers.getBuffer(1).pvBuffer = null;
                decodeBuffers.getBuffer(1).cbBuffer = 0;
                
                IntByReference qopResult = new IntByReference();
                assertOk(Secur32X.INSTANCE.DecryptMessage(serverCtx, decodeBuffers, 0, qopResult));
                
                Assert.assertEquals("QOP not correct", 0, qopResult.getValue());
                SSPICommon.printHexDump(decodeBuffers.getBuffer(0).getBytes());
                SSPICommon.printHexDump(decodeBuffers.getBuffer(1).getBytes());
                
                Assert.assertArrayEquals("Message did not survice wrap/decode roundtrip", input, decodeBuffers.getBuffer(1).getBytes());

                Memory packageMemory = new Memory(input.length + sizes.cbSecurityTrailer + sizes.cbBlockSize);
                packageMemory.write(sizes.cbSecurityTrailer, input, 0, input.length);
                
                ManagedSecBufferDesc encodeBuffers = new ManagedSecBufferDesc(3);
                encodeBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
                encodeBuffers.getBuffer(0).pvBuffer = packageMemory.share(0);
                encodeBuffers.getBuffer(0).cbBuffer = sizes.cbSecurityTrailer;
                encodeBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
                encodeBuffers.getBuffer(1).pvBuffer = packageMemory.share(sizes.cbSecurityTrailer);
                encodeBuffers.getBuffer(1).cbBuffer = input.length;
                encodeBuffers.getBuffer(2).BufferType = SspiX.SECBUFFER_PADDING;
                encodeBuffers.getBuffer(2).pvBuffer = packageMemory.share(sizes.cbSecurityTrailer + input.length);
                encodeBuffers.getBuffer(2).cbBuffer = sizes.cbBlockSize;
                
                Secur32X.INSTANCE.EncryptMessage(serverCtx, 0, encodeBuffers, 0);
        
                byte[] data = new byte[
                        encodeBuffers.getBuffer(0).cbBuffer
                        + encodeBuffers.getBuffer(1).cbBuffer
                        + encodeBuffers.getBuffer(2).cbBuffer
                        ];

                encodeBuffers.getBuffer(0).pvBuffer.read(0, data, 0, encodeBuffers.getBuffer(0).cbBuffer);
                encodeBuffers.getBuffer(1).pvBuffer.read(0, data, encodeBuffers.getBuffer(0).cbBuffer, encodeBuffers.getBuffer(1).cbBuffer);
                encodeBuffers.getBuffer(2).pvBuffer.read(0, data, encodeBuffers.getBuffer(0).cbBuffer + encodeBuffers.getBuffer(1).cbBuffer, encodeBuffers.getBuffer(2).cbBuffer);
                SSPICommon.printHexDump(data);
                
                MessageProp prop2 = new MessageProp(false);
                byte[] unwrapped = ctx.unwrap(data, 0, data.length, prop2);
                
                Assert.assertArrayEquals("Message did not survice wrap/decode roundtrip", input, unwrapped);
                Assert.assertTrue("Privacy was not indicated", prop2.getPrivacy());
                SSPICommon.printHexDump(unwrapped);
                
                System.out.println("------------------ VerifySignature ----------------------------------");
                
                MessageProp prop3 = new MessageProp(false);
                byte[] signature = ctx.getMIC(input, 0, input.length, prop3);
                
                Memory verificationMemory = new Memory(signature.length + input.length);
                verificationMemory.write(0, signature, 0, signature.length);
                verificationMemory.write(signature.length, input, 0, input.length);
                
                ManagedSecBufferDesc signVerifyBuffers = new ManagedSecBufferDesc(2);
                signVerifyBuffers.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
                signVerifyBuffers.getBuffer(0).pvBuffer = verificationMemory.share(0);
                signVerifyBuffers.getBuffer(0).cbBuffer = signature.length;
                signVerifyBuffers.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
                signVerifyBuffers.getBuffer(1).pvBuffer = verificationMemory.share(signature.length);
                signVerifyBuffers.getBuffer(1).cbBuffer = input.length;
                
                assertOk(Secur32X.INSTANCE.VerifySignature(serverCtx, signVerifyBuffers, 0, null));
                        
                System.out.println("------------------ MakeSignature ----------------------------------");
                
                Memory makeSignatureMemory = new Memory(sizes.cbMaxSignature + input.length);
                makeSignatureMemory.write(0, input, 0, input.length);
                
                ManagedSecBufferDesc makeSigBuffer = new ManagedSecBufferDesc(2);
                makeSigBuffer.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
                makeSigBuffer.getBuffer(0).pvBuffer = makeSignatureMemory.share(input.length);
                makeSigBuffer.getBuffer(0).cbBuffer = sizes.cbMaxSignature;
                makeSigBuffer.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
                makeSigBuffer.getBuffer(1).pvBuffer = makeSignatureMemory.share(0);
                makeSigBuffer.getBuffer(1).cbBuffer = input.length;
                
                assertOk(Secur32X.INSTANCE.MakeSignature(serverCtx, 0, makeSigBuffer, 0));

                byte[] makeSigResult = makeSigBuffer.getBuffer(0).getBytes();
                
                MessageProp prop4 = new MessageProp(false);
                ctx.verifyMIC(makeSigResult, 0, makeSigResult.length, input, 0, input.length, prop4);
                
                return null;
            }

        });
    }
    
    private void testAcceptor(final String targetSPN, final String securityPackage, final Oid gssMech) throws Exception {
        Subject credentials = SSPIProvider.createSubjectForCurrentUser(GSSCredential.ACCEPT_ONLY);
        Security.insertProviderAt(new SSPIProvider(), 1);

        final Sspi.TimeStamp clientTimestamp = new Sspi.TimeStamp();
        final Sspi.CredHandle clientCred = new Sspi.CredHandle();
        assertOk(Secur32X.INSTANCE.AcquireCredentialsHandle(null, securityPackage, SspiX.SECPKG_CRED_OUTBOUND, null, null, null, null, clientCred, clientTimestamp));
        
        Subject.doAs(credentials, new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                GSSContext serverCtx = GSSManager.getInstance().createContext((GSSCredential) null);

                Sspi.CtxtHandle clientCtx = new Sspi.CtxtHandle();
                IntByReference clientCtxAttr = new IntByReference();
                int clientRC = W32Errors.SEC_I_CONTINUE_NEEDED;
                byte[] serverReply = new byte[0];
                
                do {
                    byte[] clientToken = new byte[0];
                    if (clientRC == W32Errors.SEC_I_CONTINUE_NEEDED) {
                        ManagedSecBufferDesc clientBuffer = new ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
                        ManagedSecBufferDesc serverBuffer = (serverReply == null || serverReply.length == 0) ?
                                null :
                                new ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, serverReply);
                        clientRC = Secur32X.INSTANCE.InitializeSecurityContext(
                                clientCred,
                                clientCtx.isNull() ? null : clientCtx,
                                targetSPN,
                                SspiX.ISC_REQ_CONFIDENTIALITY,
                                0,
                                SspiX.SECURITY_NATIVE_DREP,
                                serverBuffer,
                                0,
                                clientCtx,
                                clientBuffer,
                                clientCtxAttr,
                                null);

                        if(clientRC != W32Errors.SEC_E_OK && clientRC != W32Errors.SEC_I_CONTINUE_NEEDED) {
                            throw new RuntimeException("AcceptSecurityContext failed: " + WinErrorSecMap.resolveString(clientRC));
                        }
                        
                        if(clientBuffer.getBuffer(0).cbBuffer > 0) {
                            clientToken = clientBuffer.getBuffer(0).getBytes();
                        } else {
                            clientToken = new byte[0];
                        }
                    }
                    serverReply = serverCtx.acceptSecContext(clientToken, 0, clientToken.length);
                } while (clientRC != W32Errors.SEC_E_OK || (! serverCtx.isEstablished()));
                
                Assert.assertTrue("Confidentiality not negotiated (Server)", serverCtx.getConfState());
                assertBitSet("Confidentiality not negotiated (Client)", clientCtxAttr.getValue(), SspiX.ISC_REQ_CONFIDENTIALITY);

                Assert.assertTrue("Sequence Detection not negotiated (Server)", serverCtx.getSequenceDetState());
                assertBitSet("Sequence Detection not negotiated (Client)", clientCtxAttr.getValue(), SspiX.ISC_REQ_SEQUENCE_DETECT);
                
                Assert.assertTrue("Replay Detection not negotiated (Server)", serverCtx.getReplayDetState());
                assertBitSet("Replay Detection not negotiated (Client)", clientCtxAttr.getValue(), SspiX.ISC_REQ_REPLAY_DETECT);
                
                SspiX.SecPkgContext_Sizes sizes = new SspiX.SecPkgContext_Sizes();
                assertOk(Secur32X.INSTANCE.QueryContextAttributes(clientCtx, SspiX.SECPKG_ATTR_SIZES, sizes));
                
                byte[] input = ("Hallo Welt - " + new Date()).getBytes();
                
                byte[] wrapped = serverCtx.wrap(input, 0, input.length, new MessageProp(true));
                
                SSPICommon.printHexDump(wrapped);
                
                Memory wrappedMemory = new Memory(wrapped.length);
                wrappedMemory.write(0, wrapped, 0, wrapped.length);
                
                ManagedSecBufferDesc decodeBuffers = new ManagedSecBufferDesc(2);
                decodeBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_STREAM;
                decodeBuffers.getBuffer(0).pvBuffer = wrappedMemory;
                decodeBuffers.getBuffer(0).cbBuffer = (int) wrappedMemory.size();
                decodeBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
                decodeBuffers.getBuffer(1).pvBuffer = null;
                decodeBuffers.getBuffer(1).cbBuffer = 0;
                
                IntByReference qopResult = new IntByReference();
                assertOk(Secur32X.INSTANCE.DecryptMessage(clientCtx, decodeBuffers, 0, qopResult));
                
                Assert.assertEquals("QOP not correct", 0, qopResult.getValue());
                SSPICommon.printHexDump(decodeBuffers.getBuffer(0).getBytes());
                SSPICommon.printHexDump(decodeBuffers.getBuffer(1).getBytes());
                
                Assert.assertArrayEquals("Message did not survice wrap/decode roundtrip", input, decodeBuffers.getBuffer(1).getBytes());

                Memory packageMemory = new Memory(input.length + sizes.cbSecurityTrailer + sizes.cbBlockSize);
                packageMemory.write(sizes.cbSecurityTrailer, input, 0, input.length);
                
                ManagedSecBufferDesc encodeBuffers = new ManagedSecBufferDesc(3);
                encodeBuffers.getBuffer(0).BufferType = SspiX.SECBUFFER_TOKEN;
                encodeBuffers.getBuffer(0).pvBuffer = packageMemory.share(0);
                encodeBuffers.getBuffer(0).cbBuffer = sizes.cbSecurityTrailer;
                encodeBuffers.getBuffer(1).BufferType = SspiX.SECBUFFER_DATA;
                encodeBuffers.getBuffer(1).pvBuffer = packageMemory.share(sizes.cbSecurityTrailer);
                encodeBuffers.getBuffer(1).cbBuffer = input.length;
                encodeBuffers.getBuffer(2).BufferType = SspiX.SECBUFFER_PADDING;
                encodeBuffers.getBuffer(2).pvBuffer = packageMemory.share(sizes.cbSecurityTrailer + input.length);
                encodeBuffers.getBuffer(2).cbBuffer = sizes.cbBlockSize;
                
                Secur32X.INSTANCE.EncryptMessage(clientCtx, 0, encodeBuffers, 0);
        
                byte[] data = new byte[
                        encodeBuffers.getBuffer(0).cbBuffer
                        + encodeBuffers.getBuffer(1).cbBuffer
                        + encodeBuffers.getBuffer(2).cbBuffer
                        ];

                encodeBuffers.getBuffer(0).pvBuffer.read(0, data, 0, encodeBuffers.getBuffer(0).cbBuffer);
                encodeBuffers.getBuffer(1).pvBuffer.read(0, data, encodeBuffers.getBuffer(0).cbBuffer, encodeBuffers.getBuffer(1).cbBuffer);
                encodeBuffers.getBuffer(2).pvBuffer.read(0, data, encodeBuffers.getBuffer(0).cbBuffer + encodeBuffers.getBuffer(1).cbBuffer, encodeBuffers.getBuffer(2).cbBuffer);
                SSPICommon.printHexDump(data);
                
                MessageProp prop2 = new MessageProp(false);
                byte[] unwrapped = serverCtx.unwrap(data, 0, data.length, prop2);
                
                Assert.assertArrayEquals("Message did not survice wrap/decode roundtrip", input, unwrapped);
                Assert.assertTrue("Privacy was not indicated", prop2.getPrivacy());
                SSPICommon.printHexDump(unwrapped);
                
                System.out.println("------------------ VerifySignature ----------------------------------");
                
                MessageProp prop3 = new MessageProp(false);
                byte[] signature = serverCtx.getMIC(input, 0, input.length, prop3);
                
                Memory verificationMemory = new Memory(signature.length + input.length);
                verificationMemory.write(0, signature, 0, signature.length);
                verificationMemory.write(signature.length, input, 0, input.length);
                
                ManagedSecBufferDesc signVerifyBuffers = new ManagedSecBufferDesc(2);
                signVerifyBuffers.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
                signVerifyBuffers.getBuffer(0).pvBuffer = verificationMemory.share(0);
                signVerifyBuffers.getBuffer(0).cbBuffer = signature.length;
                signVerifyBuffers.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
                signVerifyBuffers.getBuffer(1).pvBuffer = verificationMemory.share(signature.length);
                signVerifyBuffers.getBuffer(1).cbBuffer = input.length;
                
                assertOk(Secur32X.INSTANCE.VerifySignature(clientCtx, signVerifyBuffers, 0, null));
                        
                System.out.println("------------------ MakeSignature ----------------------------------");
                
                Memory makeSignatureMemory = new Memory(sizes.cbMaxSignature + input.length);
                makeSignatureMemory.write(0, input, 0, input.length);
                
                ManagedSecBufferDesc makeSigBuffer = new ManagedSecBufferDesc(2);
                makeSigBuffer.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
                makeSigBuffer.getBuffer(0).pvBuffer = makeSignatureMemory.share(input.length);
                makeSigBuffer.getBuffer(0).cbBuffer = sizes.cbMaxSignature;
                makeSigBuffer.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
                makeSigBuffer.getBuffer(1).pvBuffer = makeSignatureMemory.share(0);
                makeSigBuffer.getBuffer(1).cbBuffer = input.length;
                
                assertOk(Secur32X.INSTANCE.MakeSignature(clientCtx, 0, makeSigBuffer, 0));

                byte[] makeSigResult = makeSigBuffer.getBuffer(0).getBytes();
                
                MessageProp prop4 = new MessageProp(false);
                serverCtx.verifyMIC(makeSigResult, 0, makeSigResult.length, input, 0, input.length, prop4);
                
                return null;
            }

        });
    }
    
    public static String toString(MessageProp mp) {
        return String.format("{QOP: %d, Privacy: %b, MinorString: %s, MinorStatus: %d, "
                + "duplicateToken: %b, gapToken: %b, oldToken: %b, unseqToken: %b}",
                mp.getQOP(), mp.getPrivacy(), mp.getMinorString(), mp.getMinorStatus(),
                mp.isDuplicateToken(), mp.isGapToken(), mp.isOldToken(), mp.isUnseqToken());
    }
    
    private static void assertOk(int result) {
        Assert.assertEquals(String.format("Assertion failed (%d): %s", result, WinErrorSecMap.resolveString(result)), WinError.SEC_E_OK, result);
    }
    
    private static void assertBitSet(String message, int bitfield, int targetBit) {
        Assert.assertTrue(message, (bitfield & targetBit) == targetBit);
    }
}
