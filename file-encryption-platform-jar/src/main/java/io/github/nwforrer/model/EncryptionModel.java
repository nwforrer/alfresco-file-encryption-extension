package io.github.nwforrer.model;

import org.alfresco.service.namespace.QName;

public class EncryptionModel {
    public static final String NAMESPACE_ENCRYPTION_MODEL = "http://nwforrer.github.io/encryption/model/content/1.0";

    public static final QName ASPECT_ENCRYPTED = QName.createQName(NAMESPACE_ENCRYPTION_MODEL, "encrypted");
}
