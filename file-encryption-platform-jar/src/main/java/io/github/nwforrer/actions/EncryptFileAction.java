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
import org.bouncycastle.openpgp.PGPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.List;

public class EncryptFileAction extends ActionExecuterAbstractBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptFileAction.class);

    private final ServiceRegistry serviceRegistry;
    private final GPGEncryptionUtil gpgEncryptionUtil;

    private String publicKeyPath;

    public EncryptFileAction(ServiceRegistry serviceRegistry, GPGEncryptionUtil gpgEncryptionUtil) {
        this.serviceRegistry = serviceRegistry;
        this.gpgEncryptionUtil = gpgEncryptionUtil;
    }

    @Override
    protected void executeImpl(Action action, NodeRef nodeRef) {
        LOGGER.info("Executing encrypt file action.");

        ContentReader reader = serviceRegistry.getContentService().getReader(nodeRef, ContentModel.PROP_CONTENT);
        ContentWriter writer = serviceRegistry.getContentService().getWriter(nodeRef, ContentModel.PROP_CONTENT, true);

        try (InputStream publicKey = new FileInputStream(publicKeyPath);
             InputStream nodeContent = reader.getContentInputStream();
             OutputStream out = writer.getContentOutputStream()) {
            gpgEncryptionUtil.encryptFile(nodeContent, out, publicKey);

            // add a .pgp extension to filename
            String fileName = (String) serviceRegistry.getNodeService().getProperty(nodeRef, ContentModel.PROP_NAME);
            fileName += ".pgp";
            serviceRegistry.getNodeService().setProperty(nodeRef, ContentModel.PROP_NAME, fileName);

            serviceRegistry.getNodeService().addAspect(nodeRef, EncryptionModel.ASPECT_ENCRYPTED, null);
        } catch (Exception e) {
            LOGGER.error("Failed to encrypt file.", e);
            throw new AlfrescoRuntimeException("Failed to encrypt file", e);
        }
    }

    @Override
    protected void addParameterDefinitions(List<ParameterDefinition> list) {
        // not needed
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }
}
