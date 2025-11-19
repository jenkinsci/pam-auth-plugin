package hudson.security;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import hudson.Functions;
import hudson.security.SecurityRealm.SecurityComponents;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;

/**
 * @author Kohsuke Kawaguchi
 */
@WithJenkins
class PAMSecurityRealmTest {

    private JenkinsRule j;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    @Test
    void loadUsers() {
        assumeFalse(Functions.isWindows());

        SecurityComponents sc = new PAMSecurityRealm("sshd").getSecurityComponents();
        assertThrows(UsernameNotFoundException.class, () -> sc.userDetails2.loadUserByUsername("bogus-bogus-bogus"), "no such user");

        String name = System.getProperty("user.name");
        System.out.println(Arrays.asList(sc.userDetails2.loadUserByUsername(name).getAuthorities()));
    }
}
