package hudson.security;

import hudson.Functions;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assume.assumeFalse;

public class PAMSecurityRealmJCasCTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @BeforeClass
    public static void beforeEverythingAssumeWindows() {
        assumeFalse(Functions.isWindows());
    }

    @Test
    @ConfiguredWithCode("config.yaml")
    public void testConfigYaml() {
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertThat(securityRealm, instanceOf(PAMSecurityRealm.class));
        PAMSecurityRealm pam = (PAMSecurityRealm) securityRealm;
        assertThat(pam.serviceName, equalTo("sudo"));
    }
}
