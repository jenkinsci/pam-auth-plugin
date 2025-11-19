package hudson.security;

import hudson.Functions;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@WithJenkinsConfiguredWithCode
class PAMSecurityRealmJCasCTest {

    @BeforeAll
    static void beforeAll() {
        assumeFalse(Functions.isWindows());
    }

    @Test
    @ConfiguredWithCode("config.yaml")
    void testConfigYaml(JenkinsConfiguredWithCodeRule j) {
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertThat(securityRealm, instanceOf(PAMSecurityRealm.class));
        PAMSecurityRealm pam = (PAMSecurityRealm) securityRealm;
        assertThat(pam.serviceName, equalTo("sudo"));
    }
}
