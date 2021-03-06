package org.keycloak.rule;

import org.junit.rules.ExternalResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CryptoInitRule extends ExternalResource {

    @Override
    protected void before() throws Throwable {
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
    }
}
