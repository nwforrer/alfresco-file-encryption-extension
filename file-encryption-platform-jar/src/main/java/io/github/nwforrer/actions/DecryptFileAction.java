package io.github.nwforrer.actions;

import io.github.nwforrer.encryption.GPGEncryptionUtil;
import io.github.nwforrer.model.EncryptionModel;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.model.ContentModel;
import org.alfresco.repo.action.executer.ActionExecuterAbstractBase;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentWriter;
import org.alfresco.service.cmr.repository.NodeRef;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public class DecryptFileAction extends ActionExecuterAbstractBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptFileAction.class);

    private final ServiceRegistry serviceRegistry;
    private final GPGEncryptionUtil gpgEncryptionUtil;

    private String publicKeyPath;
    private String privateKeyPath;
    private String privateKeyPassword;

    public DecryptFileAction(ServiceRegistry serviceRegistry, GPGEncryptionUtil gpgEncryptionUtil) {
        this.serviceRegistry = serviceRegistry;
        this.gpgEncryptionUtil = gpgEncryptionUtil;
    }

    @Override
    protected void executeImpl(Action action, NodeRef nodeRef) {
        LOGGER.info("Executing decrypt file action.");

        ContentReader reader = serviceRegistry.getContentService().getReader(nodeRef, ContentModel.PROP_CONTENT);
        ContentWriter writer = serviceRegistry.getContentService().getWriter(nodeRef, ContentModel.PROP_CONTENT, true);

        try (InputStream privateKey = new FileInputStream(privateKeyPath);
             InputStream publicKey = new FileInputStream(publicKeyPath);
             InputStream nodeContent = reader.getContentInputStream();
             InputStream decryptedContent = gpgEncryptionUtil.decryptFile(nodeContent, privateKey, publicKey, privateKeyPassword.toCharArray());
             OutputStream out = writer.getContentOutputStream()) {

            IOUtils.copy(decryptedContent, out);

            // strip the .pgp extension if it exists.
            String fileName = (String) serviceRegistry.getNodeService().getProperty(nodeRef, ContentModel.PROP_NAME);
            if (fileName.endsWith(".pgp") || fileName.endsWith(".asc") || fileName.endsWith(".gpg")) {
                fileName = fileName.substring(0, fileName.length() - 4);
                serviceRegistry.getNodeService().setProperty(nodeRef, ContentModel.PROP_NAME, fileName);
            }

            serviceRegistry.getNodeService().removeAspect(nodeRef, EncryptionModel.ASPECT_ENCRYPTED);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt file.", e);
            throw new AlfrescoRuntimeException("Failed to decrypt the file.", e);
        }
    }

    @Override
    protected void addParameterDefinitions(List<ParameterDefinition> list) {
        // not needed
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public void setPrivateKeyPassword(String privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }
}

