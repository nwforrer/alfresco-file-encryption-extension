package io.github.nwforrer.encryption;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.SignatureException;
import java.util.Iterator;

@Component
public class GPGEncryptionUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(GPGEncryptionUtil.class);
    public static final String BC_PROVIDER = "BC";

    @SuppressWarnings("rawtypes")
    public InputStream decryptFile(InputStream in, InputStream privateKeyIn, InputStream publicKeyIn, char[] passwd) throws IOException, SignatureException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        Object o = pgpF.nextObject();
        PGPEncryptedDataList enc = o instanceof PGPEncryptedDataList?(PGPEncryptedDataList)o : (PGPEncryptedDataList)pgpF.nextObject();

        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn));

        while (sKey == null && it.hasNext()){
            pbe = (PGPPublicKeyEncryptedData)it.next();
            sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
        }
        if (sKey == null){
            throw new IllegalArgumentException("secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC_PROVIDER).setContentProvider(BC_PROVIDER).build(sKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        Object message = plainFact.nextObject();
        if (message instanceof PGPCompressedData){
            PGPCompressedData   cData = (PGPCompressedData)message;
            PGPObjectFactory  pgpFact = new PGPObjectFactory(cData.getDataStream());
            message = pgpFact.nextObject();
            if (message instanceof PGPLiteralData){
                return parsePGLiteralData((PGPLiteralData) message);
            }else if (message instanceof PGPOnePassSignatureList) {
                return parsePGOnePassSignatureList(publicKeyIn, (PGPOnePassSignatureList) message, pgpFact);
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }
        } else {
            throw new PGPException("unable to verify message");
        }
    }

    private InputStream parsePGOnePassSignatureList(InputStream publicKeyIn, PGPOnePassSignatureList message, PGPObjectFactory pgpFact) throws IOException, PGPException, SignatureException {
        PGPPublicKey key =readPublicKeyFromCol(publicKeyIn);
        if (key != null){
            PGPOnePassSignature ops = message.get(0);
            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC_PROVIDER), key);

            try (ByteArrayOutputStream out = new ByteArrayOutputStream();
                 PipedOutputStream pipedOutputStream = new PipedOutputStream()) {

                PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
                int ch;
                InputStream dIn = p2.getInputStream();
                while ((ch = dIn.read()) >= 0) {
                    ops.update((byte) ch);
                    out.write(ch);
                }

                PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);

                out.writeTo(pipedOutputStream);

                return pipedInputStream;
            }
        } else {
            throw new PGPException ("unable to find public key for signed file");
        }
    }

    private PipedInputStream parsePGLiteralData(PGPLiteralData message) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             PipedOutputStream pipedOutputStream = new PipedOutputStream()) {

            InputStream unc = message.getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }

            PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);

            out.writeTo(pipedOutputStream);

            return pipedInputStream;
        }
    }

    private PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null){
            return null;
        } else {
            return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BC_PROVIDER).build(pass));
        }
    }

    @SuppressWarnings("rawtypes")
    private PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
        PGPPublicKeyRing pkRing;
        PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));

        Iterator it = pkCol.getKeyRings();
        while (it.hasNext()) {
            pkRing = (PGPPublicKeyRing) it.next();
            Iterator pkIt = pkRing.getPublicKeys();
            while (pkIt.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) pkIt.next();
                if (key.isMasterKey())
                    return key;
            }
        }
        return null;
    }
}

