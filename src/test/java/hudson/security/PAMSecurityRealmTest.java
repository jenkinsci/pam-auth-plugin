package hudson.security;

import hudson.Functions;
import hudson.os.PosixAPI;
import hudson.security.SecurityRealm.SecurityComponents;
import jnr.posix.POSIX;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jvnet.hudson.test.HudsonTestCase;

import java.util.Arrays;

/**
 * @author Kohsuke Kawaguchi
 */
public class PAMSecurityRealmTest extends HudsonTestCase {
    public void testLoadUsers() {
        if (Functions.isWindows())  return; // skip on Windows

        SecurityComponents sc = new PAMSecurityRealm("sshd").getSecurityComponents();

        try {
            sc.userDetails.loadUserByUsername("bogus-bogus-bogus");
            fail("no such user");
        } catch (UsernameNotFoundException e) {
            // expected
        }

        POSIX api = PosixAPI.jnr();
        String name = api.getpwuid(api.geteuid()).getLoginName();
        System.out.println(Arrays.asList(sc.userDetails.loadUserByUsername(name).getAuthorities()));
    }
}
