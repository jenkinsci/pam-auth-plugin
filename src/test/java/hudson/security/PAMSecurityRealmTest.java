package hudson.security;

import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import hudson.Functions;
import hudson.security.SecurityRealm.SecurityComponents;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;

/**
 * @author Kohsuke Kawaguchi
 */
public class PAMSecurityRealmTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void loadUsers() {
        assumeFalse(Functions.isWindows());

        SecurityComponents sc = new PAMSecurityRealm("sshd").getSecurityComponents();

        try {
            sc.userDetails2.loadUserByUsername("bogus-bogus-bogus");
            fail("no such user");
        } catch (UsernameNotFoundException e) {
            // expected
        }


        String name = System.getProperty("user.name");
        System.out.println(Arrays.asList(sc.userDetails2.loadUserByUsername(name).getAuthorities()));
    }
}
