/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.security;

import hudson.Extension;
import hudson.Functions;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.pam.Messages;
import hudson.util.FormValidation;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;

import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Logger;

/**
 * {@link SecurityRealm} that uses Unix PAM authentication.
 *
 * @author Kohsuke Kawaguchi
 * @since 1.282
 */
public class PAMSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(PAMSecurityRealm.class.getName());

    public final String serviceName;

    @DataBoundConstructor
    public PAMSecurityRealm(String serviceName) {
        serviceName = Util.fixEmptyAndTrim(serviceName);
        if (serviceName == null) {
            serviceName = "sshd"; // use sshd as the default
        }
        this.serviceName = serviceName;
    }

    @Override
    protected synchronized UserDetails authenticate2(String username, String password) throws AuthenticationException {
        try {
            UnixUser u = new PAM(serviceName).authenticate(username, password);

            // I never understood why Acegi insists on keeping the password...
            return new User(username, "", true, true, true, true, toAuthorities(u));
        } catch (PAMException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        if (!UnixUser.exists(username)) {
            throw new UsernameNotFoundException("No such Unix user: " + username);
        }
        try {
            UnixUser u = new UnixUser(username);
            // return some dummy instance
            return new User(username, "", true, true, true, true, toAuthorities(u));
        } catch (PAMException e) {
            throw new UsernameNotFoundException("Failed to load information about Unix user: " + username, e);
        }
    }

    private static Collection<? extends GrantedAuthority> toAuthorities(UnixUser u) {
        Set<String> groups = u.getGroups();
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        for (String group : groups) {
            authorities.add(new SimpleGrantedAuthority(group));
        }
        authorities.add(AUTHENTICATED_AUTHORITY2);
        return authorities;
    }

    @Override
    public GroupDetails loadGroupByGroupname2(String groupName, boolean fetchMembers) throws UsernameNotFoundException {
        String group = groupName.startsWith("@") ? groupName.substring(1) : groupName;

        try {
            FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByGroupName(groupName);
        } catch (IOException e) {
            throw new UsernameNotFoundException(group);
        } catch (UnsupportedOperationException e) {
            throw new UsernameNotFoundException("Unable to generate the lookup service to load " + group);
        }
        return new GroupDetails() {
            @Override
            public String getName() {
                return group;
            }
        };
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.2
     */
    @Override
    public IdStrategy getUserIdStrategy() {
        return DescriptorImpl.STRATEGY;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.2
     */
    @Override
    public IdStrategy getGroupIdStrategy() {
        return DescriptorImpl.STRATEGY;
    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public String getDisplayName() {
            return Messages.PAMSecurityRealm_DisplayName();
        }

        /**
         * NSS/PAM databases are case sensitive... unless running OS-X (think different™)
         *
         * @since 1.2
         */
        private static final IdStrategy STRATEGY =
                Util.fixNull(System.getProperty("os.name")).contains("OS X")
                        ? IdStrategy.CASE_INSENSITIVE
                        : new IdStrategy.CaseSensitive();

        @RequirePOST
        public FormValidation doTest() {
            Jenkins jenkins = Jenkins.get();
            if (!jenkins.hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
            File s = new File("/etc/shadow");
            if (s.exists() && !s.canRead()) {
                // it looks like shadow password is in use, but we don't have read access
                LOGGER.fine("/etc/shadow exists but not readable");
                String shadowOwner = null;
                String shadowGroup = null;
                PosixFileAttributes fileAttributes = null;
                try {
                    fileAttributes = Files.readAttributes(s.toPath(), PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    shadowOwner = fileAttributes.owner().getName();
                    shadowGroup = fileAttributes.group().getName();
                } catch (IOException e) {
                    return FormValidation.error(Messages.PAMSecurityRealm_ReadPermission());
                } catch (UnsupportedOperationException e) {
                    return FormValidation.error(Messages.PAMSecurityRealm_UnsupportedOperation());
                }
                String user = System.getProperty("user.name") != null ? Messages.PAMSecurityRealm_User(System.getProperty("user.name")) : Messages.PAMSecurityRealm_CurrentUser();

                if (fileAttributes.permissions().contains(PosixFilePermission.GROUP_READ)) {
                    // the file is readable to group. Jenkins should be in the right group, then
                    return FormValidation.error(Messages.PAMSecurityRealm_BelongToGroup(user, shadowGroup));
                } else {
                    return FormValidation.error(Messages.PAMSecurityRealm_RunAsUserOrBelongToGroupAndChmod(shadowOwner, user, shadowGroup));
                }
            }
            return FormValidation.ok(Messages.PAMSecurityRealm_Success());
        }
    }

    @Extension
    public static DescriptorImpl install() {
        return Functions.isWindows() ? null : new DescriptorImpl();
    }
}
