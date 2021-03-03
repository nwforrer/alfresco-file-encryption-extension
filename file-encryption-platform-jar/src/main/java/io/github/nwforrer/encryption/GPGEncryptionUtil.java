package io.github.nwforrer.encryption;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

@Component
public class GPGEncryptionUtil {

    public static final String BC_PROVIDER = "BC";

    @SuppressWarnings("rawtypes")
    public void decryptFile(InputStream in, OutputStream out, InputStream privateKeyIn, InputStream publicKeyIn, char[] passwd) throws IOException, SignatureException, PGPException {
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
                parsePGLiteralData((PGPLiteralData) message, out);
            }else if (message instanceof PGPOnePassSignatureList) {
                parsePGOnePassSignatureList(publicKeyIn, (PGPOnePassSignatureList) message, pgpFact, out);
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }
        } else {
            throw new PGPException("unable to verify message");
        }
    }

    public void encryptFile(InputStream in, OutputStream out, InputStream publicKeyIn) throws IOException, PGPException {
        PGPPublicKey publicKey = readPublicKeyFromCol(publicKeyIn);
        if (publicKey != null) {
            out = new ArmoredOutputStream(out);

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES)
                            .setWithIntegrityPacket(true)
                            .setProvider(BC_PROVIDER)
            );
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(BC_PROVIDER));

            OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[8192]);
            OutputStream compressedData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(encryptedOut);

            OutputStream finalOut = new PGPLiteralDataGenerator().open(compressedData, PGPLiteralDataGenerator.BINARY, "", new Date(), new byte[8192]);

            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) > 0) {
                finalOut.write(buf, 0, len);
            }

            finalOut.close();
            compressedData.close();
            encryptedOut.close();
            out.close();
        } else {
            throw new PGPException("unable to read public key file");
        }
    }

    private void parsePGOnePassSignatureList(InputStream publicKeyIn, PGPOnePassSignatureList message, PGPObjectFactory pgpFact, OutputStream out) throws IOException, PGPException, SignatureException {
        PGPPublicKey key =readPublicKeyFromCol(publicKeyIn);
        if (key != null){
            PGPOnePassSignature ops = message.get(0);
            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC_PROVIDER), key);

            PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
            int ch;
            InputStream dIn = p2.getInputStream();
            while ((ch = dIn.read()) >= 0) {
                ops.update((byte) ch);
                out.write(ch);
            }
        } else {
            throw new PGPException ("unable to find public key for signed file");
        }
    }

    private void parsePGLiteralData(PGPLiteralData message, OutputStream out) throws IOException {
        InputStream unc = message.getInputStream();
        int ch;
        while ((ch = unc.read()) >= 0) {
            out.write(ch);
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

