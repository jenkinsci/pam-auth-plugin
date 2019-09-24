package hudson.security;

import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import hudson.Functions;
import hudson.security.SecurityRealm.SecurityComponents;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;

import static hudson.util.jna.GNUCLibrary.*;

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
            sc.userDetails.loadUserByUsername("bogus-bogus-bogus");
            fail("no such user");
        } catch (UsernameNotFoundException e) {
            // expected
        }

        String name = LIBC.getpwuid(LIBC.geteuid()).pw_name;

        System.out.println(Arrays.asList(sc.userDetails.loadUserByUsername(name).getAuthorities()));
    }
}
